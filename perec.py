import sys, getopt
import lief

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
	
#Display the dialogs part of the Resources if they exist
def dialogs(binary):
	if not binary.resources_manager.has_dialogs:
		print("'{}' has no dialogs. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	for i in binary.resources_manager.dialogs:
		print(i)

#Display the manifest part of the Resources if they exist
def manifest(binary):
	if not binary.resources_manager.has_manifest:
		print("'{}' has no manifest. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	print(binary.resources_manager.manifest)

#Display the version part of the Resources if they exist
def version(binary):
	if not binary.resources_manager.has_version:
		print("'{}' has no version. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	print(binary.resources_manager.version)


#Display the types available	
def types(binary):
	for i in binary.resources_manager.types_available:
		print(str(i).split(".")[1])

#Display infos about the icons and save them	
def icons(binary):
	if not binary.resources_manager.has_icons:
		print("'{}' has no icons. Abort!".format(binary.name), file=sys.stderr)
		sys.exit(1)
	i=0
	for ico in binary.resources_manager.icons:
		print(ico)
		print("Icon saved as " + binary.name+str(i)+".ico")
		ico.save(binary.name+str(i)+".ico")
		i+=1

#Display the langs and sublangs
def langue(binary):
	 print(binary.resources_manager.langs_available)
	 print(binary.resources_manager.sublangs_available)


def iter(binary,arg):
	pass
	#TODO

def main(argv):

	try:
		opts, args = getopt.getopt(argv,"i:ats")
	except getopt.GetoptError:
		sys.exit(2)

	for opt, arg in opts:

		if opt == '-i':
			binary = open_pe(arg)
			path=arg

		if opt == '-a':
			resmanager(binary)
			sys.exit()	

		if opt == '-t':
			types(binary)
			sys.exit()	

		if opt == '-s':
			iter(binary,arg)
			sys.exit()	






if __name__ == "__main__":
   main(sys.argv[1:])