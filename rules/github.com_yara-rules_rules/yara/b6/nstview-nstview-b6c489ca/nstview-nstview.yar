rule nstview_nstview {
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3871888a0c1ac4270104918231029a56"
	strings:
		$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
	condition:
		all of them
}