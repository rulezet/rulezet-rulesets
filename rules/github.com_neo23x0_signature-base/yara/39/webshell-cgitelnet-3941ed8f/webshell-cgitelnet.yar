rule WebShell_cgitelnet {
	meta:
		description = "PHP Webshells Github Archive - file cgitelnet.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"
		id = "b02d8549-ebfe-522c-9a6d-8657273da3ed"
	strings:
		$s9 = "# Author Homepage: http://www.rohitab.com/" fullword
		$s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
		$s18 = "# in a command line on Windows NT." fullword
		$s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
	condition:
		2 of them
}