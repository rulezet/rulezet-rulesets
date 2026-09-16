rule WebShell_RemExp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
		id = "274c8816-2711-5f12-937e-549ec2d57ce1"
	strings:
		$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
		$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
		$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
		$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
		$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
	condition:
		all of them
}