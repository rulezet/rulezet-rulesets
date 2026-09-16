rule FSO_s_RemExp_2 {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b69670ecdbb40012c73686cd22696eeb"
	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
	condition:
		all of them
}