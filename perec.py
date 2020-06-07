import sys, getopt
import lief


def usage():
	print("python3 perec.p -i <inputfile> -o <outputDir>  [option]")
	print("-i <inputfile> : Input File")
	print("-o <outputDir> : Output Directory")
	print("-t : Display PE resources found")
	print("-a : Display all PE resources")
	print("-f : Display file infos")
	print("""-s <ICON/DIALOG/VERSION/MANIFEST>: Display PE resource with the possibility to save it if -o was used before, for icons -o is mandatory to save the icons""")
	
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


	
def iter(binary,arg,found_o,output):
	etypes=types(binary)
	if arg not in etypes:
		print(format(binary.name)+" has no "+arg+". Abort!", file=sys.stderr)
		sys.exit(1)
	
	if arg =="ICON":
		icons(binary,found_o,output)

	elif arg =="BITMAP":
		print("BITMAP")
		#TODO

	elif arg =="CURSOR":
		print("CURSOR")
		#TODO

	elif arg =="DIALOG":
		dialogs(binary,found_o,output)

	elif arg =="VERSION":
		version(binary,found_o,output)

	elif arg =="MANIFEST":
		manifest(binary,found_o,output)


#Print output message
def output_help(found_o):
	if not found_o:
		print("use -o path/ to save files")


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
			print(bytes(binary.resources.childs[0].childs[0].childs[0].content))
			sys.exit()	

			#This is usef for testing
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