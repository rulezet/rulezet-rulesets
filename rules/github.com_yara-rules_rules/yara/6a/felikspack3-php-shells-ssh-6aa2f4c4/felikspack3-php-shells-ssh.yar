rule FeliksPack3___PHP_Shells_ssh {
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "1aa5307790d72941589079989b4f900e"
	strings:
		$s0 = "eval(gzinflate(str_rot13(base64_decode('"
	condition:
		all of them
}