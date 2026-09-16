rule Debug_dllTest_2 {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}