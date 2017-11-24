import pefile
import sys
filename = "tursh.exe"
with open(filename, "rb") as s:
    r = s.read()
pe = pefile.PE(filename)
offset = pe.get_overlay_data_start_offset()
c=0
h=0
niit=""
for i in range(0,len(r)):
	if c==16:
		niit+="        "
		i=i-16
		for i in range(i,i+16):
			tmp=r[i]
			if ord(tmp)<=31:
				niit+="."
			else:
				niit+=tmp
		niit+="\n"		
		c=0 
	if c==0:
		niit+=format(h, '08X')
		h=h+16
	a=ord(r[i])
	niit+=format(a, '02X')
	c=c+1
print niit
	
