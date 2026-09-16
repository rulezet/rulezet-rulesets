rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}