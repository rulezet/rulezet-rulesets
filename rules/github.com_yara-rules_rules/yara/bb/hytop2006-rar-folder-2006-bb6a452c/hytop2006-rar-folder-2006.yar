rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}