from PIL import Image
import os
import sys

def generate_header(image_path, header_path):
    try:
        if not os.path.exists(image_path):
            print(f"Error: {image_path} not found.")
            return False
            
        img = Image.open(image_path)
        img = img.resize((16, 16), Image.Resampling.LANCZOS)
        
        # Save as ICO in memory
        import io
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='ICO')
        icon_bytes = byte_arr.getvalue()
        
        # Write header
        with open(header_path, 'w') as f:
            f.write("#pragma once\n")
            f.write(f"// Generated from {image_path}\n")
            f.write(f"const unsigned char icon_data[] = {{\n")
            
            for i, b in enumerate(icon_bytes):
                if i % 16 == 0:
                    f.write("  ")
                f.write(f"0x{b:02X}, ")
                if (i + 1) % 16 == 0:
                    f.write("\n")
            
            f.write("};\n")
            
        print(f"Success: {header_path} generated ({len(icon_bytes)} bytes).")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    src = r"d:\GitHub\patch-manager-master\icon.jpg"
    dst = r"d:\GitHub\patch-manager-master\PatchPlugin\icon_data.h"
    generate_header(src, dst)
