rule elmaliseker_asp {
	meta:
		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
	strings:
		$s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
		$s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
		$s2 = "dim zombie_array,special_array"
		$s3 = "http://vnhacker.org"
	condition:
		1 of them
}