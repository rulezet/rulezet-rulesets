rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}