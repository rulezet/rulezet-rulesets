rule webshell_jsp_12302  : webshell{
	meta:
		description = "Web Shell - file 12302.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3930518ea57d899457a62f372205f7f"
	strings:
		$s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
		$s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
	condition:
		all of them
}