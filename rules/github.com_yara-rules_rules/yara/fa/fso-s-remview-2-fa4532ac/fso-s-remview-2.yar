rule FSO_s_remview_2 {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"
	strings:
		$s0 = "<xmp>$out</"
		$s1 = ".mm(\"Eval PHP code\")."
	condition:
		all of them
}