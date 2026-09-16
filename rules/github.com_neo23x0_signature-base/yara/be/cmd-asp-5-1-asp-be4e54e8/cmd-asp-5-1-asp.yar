rule cmd_asp_5_1_asp {
	meta:
		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
		id = "fc204ab8-892d-5435-a737-a185ca32e938"
	strings:
		$s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
		$s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		1 of them
}