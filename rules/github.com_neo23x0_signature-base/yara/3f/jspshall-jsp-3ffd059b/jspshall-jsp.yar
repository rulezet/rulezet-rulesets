rule jspshall_jsp {
	meta:
		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"
		id = "4bccad33-d26e-52c2-b7f8-802f2c8f3889"
	strings:
		$s0 = "kj021320"
		$s1 = "case 'T':systemTools(out);break;"
		$s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
	condition:
		2 of them
}