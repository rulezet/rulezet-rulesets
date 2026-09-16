rule WinX_Shell_html {
	meta:
		description = "Semi-Auto-generated  - file WinX Shell.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		id = "fe02d995-4375-5ce9-aabe-fae5d29278d3"
	strings:
		$s0 = "WinX Shell"
		$s1 = "Created by greenwood from n57"
		$s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
	condition:
		2 of them
}