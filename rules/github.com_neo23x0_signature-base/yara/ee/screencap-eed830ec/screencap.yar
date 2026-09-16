rule screencap {
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "51139091dea7a9418a50f2712ea72aa6"
		id = "0c1b71d3-ad54-5230-b1ab-971647e76139"
	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"
	condition:
		all of them
}