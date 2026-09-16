rule webshell_jsp_k8cmd {
	meta:
		description = "Web Shell - file k8cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b39544415e692a567455ff033a97a682"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
	condition:
		all of them
}