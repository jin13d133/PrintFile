import pefile
import math
import pydasm
import hexlify
def H(data):
	if not data:
		return 0
	entropy = 0
	for x in range(256):
		p_x = float(data.count(chr(x)))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy


pe =pefile.PE('tursh.exe')
#print( pe.print_info())



for section in pe.sections:
	print str(section.Name)+" __  "+str(hex(section.VirtualAddress))+"   "+str(hex(section.Misc_VirtualSize))+"   "+str(section.SizeOfRawData )

i = pydasm.get_instruction('\x90', pydasm.MODE_32)
print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
i = pydasm.get_instruction('\x8B\x04\xBD\xE8\x90\x00\x01', pydasm.MODE_32)
print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)

for section in pe.sections:
	print section.Name, H(section.get_data())
#print pe.sections[0].get_data()

ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()[ep:ep+100]
offset = 0
while offset < len(data):
	i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
	print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
	offset += i.length


print("[*] Listing DOS_HEADER fields...")
for keys in pe.DOS_HEADER.__keys__:
	for field in keys:
		print('\t' + field)
for field in pe.DOS_HEADER.dump():
    print(field)
print("[*] Number of data directories = %d" % pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print('\t' + data_directory.name)

# for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
#     print(data_dir)

print pe.sections[2].get_data()


