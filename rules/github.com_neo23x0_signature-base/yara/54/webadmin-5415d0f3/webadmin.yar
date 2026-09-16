rule webadmin {
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3a90de401b30e5b590362ba2dde30937"
		id = "615d87f8-9094-5994-aea1-d7276623fbca"
	strings:
		$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
	condition:
		all of them
}