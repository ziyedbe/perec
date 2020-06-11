import sys, getopt
import lief
import string
import binascii

def usage():
	print("python3 perec.p -i <inputfile> -o <outputDir>  [option]")
	print("-i <inputfile> : Input File")
	print("-o <outputDir> : Output Directory")
	print("-t : Display PE resources found")
	print("-a : Display all PE resources supported by lief resources manager")
	print("-f : Display file infos")
	print("""-s <ICON/DIALOG/VERSION/MANIFEST>: Display PE resource with the possibility to save it if -o was used before""")

	print("---------------------------------------------")
	print("-------------Supported Resources-------------")
	print("\tCURSOR : Save cursor files to directory") #Parsed from raw data
	print("\tBITMAP : Save bitmap files to directory") #Parsed from raw data
	print("\tICON : Display information and save icon files to directory") # Used lief resources manager
	print("\tMENU : Display or Save menu files to directory") #Parsed from raw data
	print("\tDIALOG : Display or Save dialog files to directory") # Used lief resources manager
	print("\tSTRING : Display or Save string files to directory") #Parsed from raw data
	print("\tRCDATA : Save rcdata files to directory") #Parsed from raw data
	print("\tMESSAGETABLE : Display or Save messagetable files to directory") #Parsed from raw data
	print("\tVERSION : Display or Save version files to directory") # Used lief resources manager
	print("\tMANIFEST : Display or Save manifest file to directory") # Used lief resources manager



#Open the PE file and parse it using lief
def open_pe(arg):
	binary = lief.parse(arg)
	if not binary.has_resources:
		print("'{}' has no resources. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
		
	return binary

#Display all the content of the Resources
def resmanager(binary):
	resource_manager = binary.resources_manager
	print(resource_manager)
	
#Display the dialogs part of the Resources if they exist + option to save it to file
def dialogs(binary,found_o,output):
	if not binary.resources_manager.has_dialogs:
		print("'{}' has no dialogs. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	j=0
	for i in binary.resources_manager.dialogs:
		print(i)
		if found_o:
			f = open(output+binary.name+"_"+"dialog"+str(j)+".txt","w")
			f.write(str(i))
			f.close()
		j+=1
	output_help(found_o)			

#Display the manifest part of the Resources if they exist + option to save it to file
def manifest(binary,found_o,output):
	if not binary.resources_manager.has_manifest:
		print("'{}' has no manifest. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	print(binary.resources_manager.manifest)
	if found_o:
		f = open(output+binary.name+"_"+"manifest.xml","w")
		f.write(binary.resources_manager.manifest)
		f.close()
	output_help(found_o)

#Display the version part of the Resources if they exist + option to save it to file
def version(binary,found_o,output):
	if not binary.resources_manager.has_version:
		print("'{}' has no version. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	print(binary.resources_manager.version)
	if found_o:
			f = open(output+binary.name+"_"+"version.txt","w")
			f.write(str(binary.resources_manager.version))
			f.close()
	output_help(found_o)

#Display the types available	
def types(binary):
	etypes=[]
	for i in binary.resources_manager.types_available:
		etypes.append(str(i).split(".")[1])
	return etypes

#Display infos about the icons and save them + option to save it to file	
def icons(binary,found_o,output):
	if not binary.resources_manager.has_icons:
		print("'{}' has no icons. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	i=0
	for ico in binary.resources_manager.icons:
		print(ico)
		
		if found_o:
			print("Icon saved as " + binary.name+str(i)+".ico")
			ico.save(output+binary.name+str(i)+".ico")
		i+=1
	output_help(found_o)


#Display the langs and sublangs
def langue(binary):
	 print(binary.resources_manager.langs_available)
	 print(binary.resources_manager.sublangs_available)

def File_Info(binary):
	
	print("\n\n ********fixed_file_info:********** \n\n")
	print( binary.resources_manager.version.fixed_file_info)
	print("file_flags : ", binary.resources_manager.version.fixed_file_info.file_flags)
	print("file_flags_mask : ", binary.resources_manager.version.fixed_file_info.file_flags_mask)
	print("file_subtype : ", binary.resources_manager.version.fixed_file_info.file_subtype)
	print("\n\n ********string_file_info:********** \n\n")
	print( binary.resources_manager.version.string_file_info)
	print("\n\n ********var_file_info:********** \n\n")
	print( binary.resources_manager.version.var_file_info)

def cursor(binary,found_o,output):
	idd=fetch_ID(binary,"CURSOR")
	z=0
	if not found_o:
		print("Please specify an output folder to save the cursor files")
		print("Example : python3 perec.py -i FileZilla.exe -o out/ -s CURSOR")
	for i in binary.resources.childs[idd].childs:
		for j in i.childs:
			hexstr="".join("%02x" % k for k in j.content)
			
			hexstr="00000200010020200000"+hexstr[:8]+"3401000016000000"+hexstr[8::] # should be generalized
			hexstr=hexstr+"0"*(346*2-len(hexstr)) # should be generalized
			if found_o:
				with open(output+binary.name+"_"+str(z)+'.cur', 'wb') as fout:
					fout.write(binascii.unhexlify(hexstr))
					print("Cursor saved under :"+output+binary.name+"_"+str(z)+'.cur')
					z+=1
			#RAW data extracted, need for parsing later

def bitmap(binary,found_o,output):
	idd=fetch_ID(binary,"BITMAP")
	z=0
	if not found_o:
		print("Please specify an output folder to save the bitmap files")
		print("Example : python3 perec.py -i FileZilla.exe -o out/ -s BITMAP")
	for i in binary.resources.childs[idd].childs:
		
		for j in i.childs:
			hexstr="".join("%02x" % k for k in j.content)
			magic = "424d"
			header = "740600000000000072000000"
			hexstr=magic+header+hexstr
			
			if found_o:
				with open(output+binary.name+"_"+str(z)+'.bmp', 'wb') as fout:
					fout.write(binascii.unhexlify(hexstr))
					print("Bitmap saved under :"+output+binary.name+"_"+str(z)+'.bmp')
					z+=1
			
			
def rcdata(binary,found_o,output):
	idd=fetch_ID(binary,"RCDATA")
	z=0
	if not found_o:
		print("Please specify an output folder to save the rcdata files")
		print("Example : python3 perec.py -i FileZilla.exe -o out/ -s RCDATA")
		sys.exit()	
	for i in binary.resources.childs[idd].childs:
		for j in range(len(i.childs)):
			ch = i.childs[j].content
			
			hexstr="".join("%02x" % k for k in ch)
			if found_o:
				with open(output+binary.name+"_rcdata_"+str(z), 'wb') as fout:
					fout.write(binascii.unhexlify(hexstr))
					print("File saved under :"+output+binary.name+"_rcdata_"+str(z))
			z+=1

def group_icon(binary):
	idd=fetch_ID(binary,"GROUP_ICON")
	z=0
	for i in binary.resources.childs[idd].childs:
		for j in i.childs:
			print("----------GROUP_ICON-"+str(z)+"------------------")
			print(bytes(j.content))
			z+=1
			#RAW data extracted, need for parsing later


def sstring(binary,found_o,output) :
	idd=fetch_ID(binary,"STRING")
	z=0
	for i in binary.resources.childs[idd].childs:
		for j in i.childs:
			
			ch = j.content
			final = "".join(chr(x) for x in ch if chr(x) in string.printable)
			if found_o:
				with open(output+binary.name+"_string"+str(z)+'.txt', 'w') as fout:
					fout.write(final)
				print("String file saved under "+output+binary.name+"_string"+str(z)+'.txt')
			else:
				print("-------------String-"+str(z)+"-------------------------")
				print(final)
			z+=1
	if not found_o:
		print("*************perec message**************")
		print("To save files please use")
		print("python3 perec.py -i <inputfile> -o <outputDir> -s STRING")
			

def group_cursor(binary):
	idd=fetch_ID(binary,"GROUP_CURSOR")
	for i in binary.resources.childs[idd].childs:
		for j in i.childs:
			print(bytes(j.content))
			print("---------------------------------------")
			#RAW data extracted, need for parsing later

def messagetable(binary,found_o,output):
	idd=fetch_ID(binary,"MESSAGETABLE")
	z=0
	for i in binary.resources.childs[idd].childs:
		for j in range(len(i.childs)):
			
			ch = i.childs[j].content
			final = "".join(chr(x) for x in ch if chr(x) in string.printable)
			if found_o:
				with open(output+binary.name+"_messagetable_"+str(z)+'.txt', 'w') as fout:
					fout.write(final)
				print("String file saved under "+output+binary.name+"_messagetable_"+str(z)+'.txt')
			else:
				print("-------------Messagetable-"+str(z)+"-------------------------")
				print(final)
			z+=1
			

def insert_dash(string, index):
    string=string[:index] + ' -- ' + string[index:]
    return string

def menu(binary,found_o,output):
	idd=fetch_ID(binary,"MENU")
	z=0
	for i in binary.resources.childs[idd].childs:
		for j in i.childs:
			ch=bytes(j.content)
			final = "".join(chr(x) for x in ch if chr(x) in string.printable)
			l=0
			while(l<len(final)) :
				if final[l].isupper():
					final=insert_dash(final,l)
					l=l+4
				l=l+1

			if found_o:
				with open(output+binary.name+"_Menu_"+str(z)+'.txt', 'w') as fout:
					fout.write(final)
				print("String file saved under "+output+binary.name+"_Menu_"+str(z)+'.txt')
			else:
				print("-------------Menu-"+str(z)+"-------------------------")
				print(final)
			z+=1

def iter(binary,arg,found_o,output):
	etypes=types(binary)
	if arg not in etypes:
		print(format(binary.name)+" has no "+arg+". Abort!", file=sys.stderr)
		print("Please choose from the list below")
		print(types(binary))
		sys.exit(1)
	
	if arg =="ICON":
		icons(binary,found_o,output) # Done

	elif arg =="BITMAP":
		bitmap(binary,found_o,output) # Need few fixes

	elif arg =="MENU":
		menu(binary,found_o,output) # Need few fixes

	elif arg =="CURSOR":
		cursor(binary,found_o,output) # Need few fixes

	elif arg =="RCDATA":
		rcdata(binary,found_o,output) # Done

	elif arg =="GROUP_ICON":
		group_icon(binary) # This will be ignored, but it will be possible to see raw data only for now

	elif arg =="STRING":
		sstring(binary,found_o,output) # Done

	elif arg =="GROUP_CURSOR":
		group_cursor(binary) # This will be ignored, but it will be possible to see raw data only for now

	elif arg =="MESSAGETABLE":
		messagetable(binary,found_o,output) # Done
		
	elif arg =="DIALOG":
		dialogs(binary,found_o,output) # Done

	elif arg =="VERSION":
		version(binary,found_o,output) # Done

	elif arg =="MANIFEST":
		manifest(binary,found_o,output) # Done


#Print output message
def output_help(found_o):
	if not found_o:
		print("use -o path/ to save files")



def fetch_ID(binary,arg):
	d = {"CURSOR":1,"BITMAP":2,"ICON":3,"MENU":4,"DIALOG":5,
	"STRING":6,"ACCELERATOR":9,"RCDATA":10,
	"MESSAGETABLE":11,"GROUP_CURSOR":12,
	"GROUP_ICON":14,"VERSION":16,"MANIFEST":24}
	s=binary.resources.childs
	j=0
	for i in s:
		if i.id == d[arg]:
			return j
		j+=1

def main(argv):
	found_o=False
	found_i=False
	output=""
	try:
		opts, args = getopt.getopt(argv,"i:o:ats:grfh")
	except getopt.GetoptError:
		sys.exit(2)

	for opt, arg in opts:


		if opt == '-h':
			usage()
			sys.exit()	


		if opt == '-i':
			binary = open_pe(arg)
			found_i=True
			path=arg

		if opt == '-o':
			found_o= True
			output=arg+"/"

		if opt == '-a':
			resmanager(binary)
			sys.exit()	

		if opt == '-t':
			print(types(binary))
			sys.exit()	

		if opt == '-s':
			iter(binary,arg,found_o,output)
			sys.exit()

			#This is used for testing
		if opt == '-g':
			#print((binary.resources.childs[5].childs[0].childs[0].content))
			idd = fetch_ID(binary,"GROUP_CURSOR")

			s = binary.resources.childs[idd]
			print(s.childs[0].childs[0].content)
			

			#This is used for testing
		if opt == '-r':
			print(binary.resources_manager)
			sys.exit()	


		if opt == '-f':
			File_Info(binary)
			sys.exit()	



	if not found_i:
		print ("-i Please specify an input file")
		print(" use -h for help")
		sys.exit()

if __name__ == "__main__":
   main(sys.argv[1:])