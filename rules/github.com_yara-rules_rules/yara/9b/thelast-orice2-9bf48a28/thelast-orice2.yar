rule thelast_orice2 {
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"
	condition:
		all of them
}