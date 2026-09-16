rule FeliksPack3___PHP_Shells_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "97f2552c2fafc0b2eb467ee29cc803c8"
		id = "91d278d5-e9ec-5a28-9a54-4549b4f0cd07"
	strings:
		$s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
		$s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
	condition:
		all of them
}