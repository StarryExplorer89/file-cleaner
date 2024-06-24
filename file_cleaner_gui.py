import tkinter as tk
from tkinter import filedialog
import os
import struct
from tkinterdnd2 import DND_FILES, TkinterDnD


def get_file_type(header):
    if header[4:8] in (b'ftyp', b'moov', b'mdat', b'free', b'skip'):
        return "mp4/mov"
    elif header[:4] == b'\x30\x26\xb2\x75':
        return "wmv"
    elif header[:4] == b'\x1A\x45\xDF\xA3':
        return "mkv"
    elif header[:2] == b'\xFF\xD8':
        return "jpeg"
    elif header[:8] == b'\x89PNG\r\n\x1A\n':
        return "png"
    elif header[:4] == b'PK\x03\x04':
        return "zip"
    elif header[:4] == b'%PDF':
        return "pdf"
    elif header[:4] == b'RIFF' and header[8:12] == b'AVI ':
        return "avi"
    else:
        return "unknown"


def get_min_chunk_size(file_type):
    if file_type == "mp4/mov":
        return 8
    elif file_type == "wmv":
        return 24
    elif file_type == "mkv":
        return 16
    elif file_type == "jpeg":
        return 2
    elif file_type == "png":
        return 8
    elif file_type == "zip":
        return 4
    elif file_type == "pdf":
        return 4
    elif file_type == "avi":
        return 12
    else:
        raise ValueError("Unknown file type")


def read_vint(file_stream):
    first_byte = file_stream.read(1)
    if not first_byte:
        return None, 0

    first_byte_value = ord(first_byte)
    length_mask = 0x80
    length = 1

    while length <= 8 and (first_byte_value & length_mask) == 0:
        length_mask >>= 1
        length += 1

    if length > 8:
        return None, 0

    length_mask = (1 << (7 - length + 1)) - 1
    value = first_byte_value & length_mask

    for _ in range(1, length):
        next_byte = file_stream.read(1)
        if not next_byte:
            return None, 0
        value = (value << 8) | ord(next_byte)

    return value, length


def find_trailing_junk_bytes(file_path):
    try:
        with open(file_path, 'rb') as file_stream:
            file_size = os.path.getsize(file_path)
            if file_size < 16:
                log_message(f"File {file_path} is too small to determine type.", "warn")
                return 0

            header = file_stream.read(16)
            file_type = get_file_type(header)

            if file_type == "unknown":
                log_message(f"Unsupported file type: {file_path}", "warn")
                return -1

            min_chunk_size = get_min_chunk_size(file_type)
            log_message(f"File type: {file_type}, Size: {file_size} bytes")

            position = 0
            last_valid_chunk_end = 0

            if file_type == "jpeg":
                # Specifically handle JPEG to find the EOI marker
                file_stream.seek(0)
                while position < file_size:
                    byte = file_stream.read(1)
                    position += 1
                    if not byte:
                        break
                    if byte == b'\xFF':
                        next_byte = file_stream.read(1)
                        position += 1
                        if next_byte == b'\xD9':  # EOI marker
                            last_valid_chunk_end = position
                            break
                # Calculate junk bytes
                junk_bytes = file_size - last_valid_chunk_end
                return junk_bytes

            elif file_type == "png":
                position = 8  # Skip the 8-byte PNG signature
                last_valid_chunk_end = position

                while position < file_size:
                    if file_size - position < 12:
                        break
                    file_stream.seek(position)
                    chunk_length = struct.unpack(">I", file_stream.read(4))[0]
                    chunk_type = file_stream.read(4)
                    position += 8 + chunk_length + 4  # Length field, Type field, Data field, CRC field
                    last_valid_chunk_end = position
                    if chunk_type == b'IEND':
                        break

                # Calculate junk bytes
                junk_bytes = file_size - last_valid_chunk_end
                return junk_bytes

            elif file_type == "mkv":
                while position < file_size:
                    remaining_bytes = file_size - position
                    if remaining_bytes < min_chunk_size:
                        break

                    file_stream.seek(position)
                    ebml_id, id_length = read_vint(file_stream)
                    if ebml_id is None:
                        break
                    chunk_length, length_length = read_vint(file_stream)
                    if chunk_length is None or chunk_length > remaining_bytes:
                        break

                    position += id_length + length_length + chunk_length
                    last_valid_chunk_end = position

                junk_bytes = file_size - last_valid_chunk_end
                return junk_bytes

            if file_type == "pdf":
                file_size = os.path.getsize(file_path)
                min_chunk_size = 1024
                eof_marker = b'%%EOF'

                with open(file_path, 'rb') as file_stream:
                    file_stream.seek(-min_chunk_size, os.SEEK_END)
                    position = file_stream.tell()
                    last_valid_chunk_end = file_size

                    while position > 0:
                        file_stream.seek(position)
                        chunk = file_stream.read(min_chunk_size)
                        eof_index = chunk.rfind(eof_marker)

                        if eof_index != -1:
                            last_valid_chunk_end = position + eof_index + len(eof_marker)
                            break

                        position -= min_chunk_size

                    junk_bytes = file_size - last_valid_chunk_end
                    return junk_bytes

            elif file_type == "zip":
                file_stream.seek(-22, os.SEEK_END)
                position = file_stream.tell()
                while position > 0:
                    file_stream.seek(position)
                    chunk = file_stream.read(min_chunk_size)
                    if chunk.startswith(b'PK\x05\x06'):
                        last_valid_chunk_end = position + 22
                        break
                    position -= 1
                junk_bytes = file_size - last_valid_chunk_end
                return junk_bytes

            else:
                while position < file_size:
                    remaining_bytes = file_size - position
                    if remaining_bytes < min_chunk_size:
                        break

                    file_stream.seek(position)
                    chunk_header = file_stream.read(min_chunk_size)
                    bytes_read = len(chunk_header)

                    if bytes_read < min_chunk_size:
                        break

                    chunk_length = 0
                    if file_type == "mp4/mov":
                        chunk_length = struct.unpack(">I", chunk_header[:4])[0]
                    elif file_type == "wmv":
                        chunk_length = struct.unpack("<Q", chunk_header[16:24])[0]
                    elif file_type == "avi":
                        chunk_length = struct.unpack("<I", chunk_header[4:8])[0] + 8
                    elif file_type == "rar":
                        chunk_length = struct.unpack("<H", chunk_header[5:7])[0] + 7

                    if chunk_length <= 0 or chunk_length > remaining_bytes:
                        break

                    position += chunk_length
                    last_valid_chunk_end = position

                junk_bytes = file_size - last_valid_chunk_end
                return junk_bytes

    except Exception as e:
        log_message(f"Error while reading file {file_path}: {str(e)}", "error")
        return -1


def remove_trailing_junk_bytes(file_path, junk_bytes):
    try:
        with open(file_path, 'rb+') as file_stream:
            file_stream.seek(0, os.SEEK_END)
            file_length = file_stream.tell()
            file_stream.truncate(file_length - junk_bytes)
        log_message(f"Truncated {file_path} to {file_length - junk_bytes} bytes")
    except Exception as e:
        log_message(f"Error while altering file {file_path}: {str(e)}", "error")
        log_message("Possible antivirus interference. Please check your antivirus settings.", "error")


def get_unique_backup_file_path(file_path):
    base_path, extension = os.path.splitext(file_path)
    backup_file_path = f"{base_path}.tag"
    counter = 1

    while os.path.exists(backup_file_path):
        backup_file_path = f"{base_path}_{counter}.tag"
        counter += 1

    return backup_file_path


def backup_trailing_junk_bytes(file_path, junk_bytes):
    try:
        backup_file_path = get_unique_backup_file_path(file_path)
        with open(file_path, 'rb') as file_stream:
            file_bytes = file_stream.read()
            junk_start_index = len(file_bytes) - junk_bytes
            junk_bytes = file_bytes[junk_start_index:]

        with open(backup_file_path, 'wb') as backup_file:
            backup_file.write(junk_bytes)
        log_message(f"Backed up trailing junk bytes to {backup_file_path}")
    except Exception as e:
        log_message(f"Error while creating .tag file for {file_path}: {str(e)}", "error")
        log_message("Possible antivirus interference. Please check your antivirus settings.", "error")


def invoke_file_cleanup(file_path):
    if not os.path.isfile(file_path):
        log_message(f"The specified file does not exist: {file_path}", "error")
        return

    # Check if the file is writable
    if not os.access(file_path, os.W_OK):
        log_message(f"Insufficient permissions to modify the file: {file_path}", "error")
        return

    log_message(f"Processing {file_path}")

    junk_bytes = find_trailing_junk_bytes(file_path)

    if junk_bytes == -1:
        return

    if junk_bytes > 1000:
        log_message(f"No trailing junk bytes found in {file_path} (false positive detected)", "warn")
        return

    if junk_bytes > 0:
        log_message(f"Trailing junk bytes found: {junk_bytes}")

        backup_trailing_junk_bytes(file_path, junk_bytes)
        remove_trailing_junk_bytes(file_path, junk_bytes)
        log_message(f"Removed trailing junk bytes from {file_path}", "success")

        # Post-cleaning verification
        new_junk_bytes = find_trailing_junk_bytes(file_path)
        if new_junk_bytes > 0:
            log_message(f"File {file_path} still has trailing junk bytes after cleaning. "
                        f"Possible antivirus interference. Please check your antivirus settings.", "error")
    else:
        log_message(f"No trailing junk bytes found in {file_path}", "warn")


class FileCleanerApp:
    def __init__(self, root):
        self.root = root
        self.version = "v1.2"
        self.title = "File Cleaner " + self.version
        self.root.title(self.title)
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        self.create_widgets()
        self.files = []

    def create_widgets(self):
        title_font = ("Poppins", 20, "bold")
        text_font = ("Poppins", 12)

        title = tk.Label(self.root, text=self.title, font=title_font)
        title.pack(padx=10, pady=10, anchor="w")

        description = tk.Label(self.root,
                               text="This app repairs corruption caused by trailing data in any file due to bad downloads or external malicious tampering. The affected bytes are stored in a separate file, ensuring that no data is deleted and can be re-appended later.",
                               font=text_font, wraplength=580, justify="left", anchor="w")
        description.pack(padx=10, pady=5, anchor="w")

        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10, anchor="w")

        self.select_files_button = tk.Button(frame, text="Select Files", command=self.select_files, font=text_font)
        self.select_files_button.pack(side=tk.LEFT)

        or_label = tk.Label(frame, text="or", font=text_font)
        or_label.pack(side=tk.LEFT, padx=0)

        self.select_dir_button = tk.Button(frame, text="Select Directory", command=self.select_directory,
                                           font=text_font)
        self.select_dir_button.pack(side=tk.LEFT)

        step2_label = tk.Label(self.root, text="Or simply drag and drop files/folders to this window", font=text_font)
        step2_label.pack(padx=10, pady=5, anchor="w")

        self.file_frame = tk.Frame(self.root)
        self.file_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(self.file_frame, width=80, height=10, font=text_font, wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar_y = tk.Scrollbar(self.file_frame, orient="vertical", command=self.log_text.yview)
        self.scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.config(yscrollcommand=self.scrollbar_y.set, state=tk.DISABLED)

        self.clean_button = tk.Button(self.root, text="Clean Files", command=self.clean_files, font=text_font)
        self.clean_button.pack(side=tk.LEFT, padx=10, pady=10)

        # Configure drag-and-drop
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.drop)

    def select_files(self):
        selected_files = filedialog.askopenfilenames()
        if selected_files:
            self.files.extend(selected_files)
            self.log_message(f"{len(selected_files)} files added.")

    def select_directory(self):
        sel_files = []
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            for root, _, files in os.walk(selected_dir):
                for file in files:
                    sel_files.append(os.path.join(root, file))
            self.files.extend(sel_files)
            self.log_message(f"{len(sel_files)} files added from directory {selected_dir}.")

    def drop(self, event):
        sel_files = []
        files = self.root.tk.splitlist(event.data)
        for file in files:
            if os.path.isdir(file):
                for root, _, files in os.walk(file):
                    for f in files:
                        sel_files.append(os.path.join(root, f))
            else:
                sel_files.append(file)
        self.files.extend(sel_files)
        self.log_message(f"{len(sel_files)} files added via drag-and-drop.")

    def log_message(self, message, tag=None):
        self.log_text.config(state=tk.NORMAL)
        if tag:
            self.log_text.insert(tk.END, str(tag).upper() + " - " + message + "\n", tag)
        else:
            self.log_text.insert(tk.END, "INFO - " + message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)
        self.log_text.tag_configure("error", foreground="red", font=("Poppins", 12, "bold"))
        self.log_text.tag_configure("warn", foreground="orange", font=("Poppins", 12))
        self.log_text.tag_configure("success", foreground="green", font=("Poppins", 12))

    def clean_files(self):
        if not self.files:
            log_message("No files have been selected for cleaning", "error")
            return

        for file in self.files:
            invoke_file_cleanup(file)

        self.files.clear()


def log_message(message, tag=None):
    app.log_message(message, tag)


if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = FileCleanerApp(root)
    root.mainloop()
