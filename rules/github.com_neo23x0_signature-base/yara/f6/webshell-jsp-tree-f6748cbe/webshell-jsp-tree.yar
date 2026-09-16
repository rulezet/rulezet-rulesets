rule webshell_jsp_tree {
	meta:
		description = "Web Shell - file tree.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
		$s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
	condition:
		all of them
}