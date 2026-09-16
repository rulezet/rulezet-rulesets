rule webshell_webshells_new_JJjsp3 {
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
	condition:
		all of them
}