rule EditServer_Webshell {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"
	strings:
		$s2 = "Server %s Have Been Configured"
		$s5 = "The Server Password Exceeds 32 Characters"
		$s8 = "9--Set Procecess Name To Inject DLL"
	condition:
		all of them
}