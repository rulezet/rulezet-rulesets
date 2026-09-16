rule webshell_jsp_list1 {
	meta:
		description = "Web Shell - file list1.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
		$s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
	condition:
		all of them
}