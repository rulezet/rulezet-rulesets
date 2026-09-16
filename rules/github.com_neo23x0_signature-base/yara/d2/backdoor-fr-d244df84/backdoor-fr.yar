rule BackDooR__fr_ {
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a79cac2cf86e073a832aaf29a664f4be"
		id = "fd0c77e8-18b7-5eb4-8ed4-87ee4c864683"
	strings:
		$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
	condition:
		all of them
}