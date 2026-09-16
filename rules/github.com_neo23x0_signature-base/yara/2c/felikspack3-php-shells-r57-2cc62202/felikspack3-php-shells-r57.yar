rule FeliksPack3___PHP_Shells_r57 {
	meta:
		description = "Webshells Auto-generated - file r57.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "903908b77a266b855262cdbce81c3f72"
		id = "14092413-27a4-5b7d-9023-0b53b3d45a12"
	strings:
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
	condition:
		all of them
}