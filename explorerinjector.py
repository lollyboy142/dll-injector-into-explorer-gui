import ctypes
import pefile
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox

# Helper functions
def rva_to_offset(pe, rva):
    return pe.get_offset_from_rva(rva)

def manual_map(dll_path, target_pid):
    with open(dll_path, 'rb') as f:
        dll_data = f.read()

    pe = pefile.PE(data=dll_data)
    kernel32 = ctypes.windll.kernel32

    PROCESS_ALL_ACCESS = 0x1F0FFF
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
    if not h_process:
        raise Exception("Failed to open target process")

    base_address = kernel32.VirtualAllocEx(
        h_process, None,
        pe.OPTIONAL_HEADER.SizeOfImage,
        0x3000, 0x40
    )
    if not base_address:
        raise Exception("Failed to allocate memory")

    if not kernel32.WriteProcessMemory(h_process, base_address, dll_data[:pe.OPTIONAL_HEADER.SizeOfHeaders], pe.OPTIONAL_HEADER.SizeOfHeaders, None):
        raise Exception("Failed to write headers")

    for section in pe.sections:
        virt_addr = base_address + section.VirtualAddress
        raw_data = section.get_data()
        if not kernel32.WriteProcessMemory(h_process, virt_addr, raw_data, len(raw_data), None):
            raise Exception(f"Failed to write section {section.Name.decode().rstrip(chr(0))}")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for import_desc in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = import_desc.dll.decode('utf-8')
            h_module = kernel32.LoadLibraryA(dll_name.encode('utf-8'))
            if not h_module:
                raise Exception(f"Failed to load {dll_name}")

            for thunk in import_desc.imports:
                if not thunk.name:
                    continue
                func_addr = kernel32.GetProcAddress(h_module, thunk.name)
                if not func_addr:
                    raise Exception(f"Failed to get {thunk.name.decode()} address")

                write_addr = base_address + thunk.address - pe.OPTIONAL_HEADER.ImageBase
                kernel32.WriteProcessMemory(h_process, write_addr, ctypes.byref(ctypes.c_void_p(func_addr)), ctypes.sizeof(ctypes.c_void_p), None)

    delta = base_address - pe.OPTIONAL_HEADER.ImageBase
    if delta != 0 and hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in base_reloc.entries:
                if reloc.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    patch_addr = base_address + reloc.rva
                    buffer = ctypes.c_ulonglong()
                    kernel32.ReadProcessMemory(h_process, patch_addr, ctypes.byref(buffer), ctypes.sizeof(buffer), None)
                    patched_value = ctypes.c_ulonglong(buffer.value + delta)
                    kernel32.WriteProcessMemory(h_process, patch_addr, ctypes.byref(patched_value), ctypes.sizeof(patched_value), None)

    entry_point = base_address + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    thread_id = ctypes.c_ulong(0)
    if not kernel32.CreateRemoteThread(h_process, None, 0, entry_point, base_address, 0, ctypes.byref(thread_id)):
        raise Exception("Failed to create remote thread")

    kernel32.CloseHandle(h_process)

# GUI Stuff
class InjectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DLL Injector into Explorer.exe")
        self.root.geometry("400x200")
        self.dll_path = None

        self.label = tk.Label(root, text="Select a DLL to inject:", font=("Arial", 12))
        self.label.pack(pady=10)

        self.select_button = tk.Button(root, text="Browse DLL", command=self.select_dll)
        self.select_button.pack(pady=5)

        self.inject_button = tk.Button(root, text="Inject!", command=self.inject, state=tk.DISABLED)
        self.inject_button.pack(pady=20)

    def select_dll(self):
        path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
        if path:
            self.dll_path = path
            self.inject_button.config(state=tk.NORMAL)

    def inject(self):
        try:
            pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == "explorer.exe":
                    pid = proc.info['pid']
                    break
            if not pid:
                raise Exception("explorer.exe not found")

            manual_map(self.dll_path, pid)
            messagebox.showinfo("Success", "DLL Injected Successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = InjectorGUI(root)
    root.mainloop()
