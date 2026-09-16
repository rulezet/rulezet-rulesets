rule webshell_Jspspyweb  : webshell{
	meta:
		description = "Web Shell - file Jspspyweb.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4e9be07e95fff820a9299f3fb4ace059"
	strings:
		$s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
		$s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
	condition:
		all of them
}