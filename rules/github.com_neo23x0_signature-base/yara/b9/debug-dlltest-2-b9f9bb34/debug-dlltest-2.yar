rule Debug_dllTest_2 {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		id = "cf81e3de-513c-584d-bc37-6504e91b170c"
	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}