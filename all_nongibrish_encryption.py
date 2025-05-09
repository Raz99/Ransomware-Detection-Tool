# text_file.txt
with open("test_folder/text_file.txt", "w") as f:
    f.write("This is a normal ASCII text file.\nNothing suspicious here.")

# binary_file.bin
with open("test_folder/binary_file.bin", "wb") as f:
    f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00")