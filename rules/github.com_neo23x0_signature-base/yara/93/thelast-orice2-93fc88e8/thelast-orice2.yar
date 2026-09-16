rule thelast_orice2 {
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
		id = "968cef9e-0163-5f4a-91e3-07510f9f4fcd"
	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"
	condition:
		all of them
}