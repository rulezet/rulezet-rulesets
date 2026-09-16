rule ZXshell2_0_rar_Folder_ZXshell {
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "246ce44502d2f6002d720d350e26c288"
		id = "621ac87e-b1f8-58d7-9328-54af5ca9b605"
	strings:
		$s0 = "WPreviewPagesn"
		$s1 = "DA!OLUTELY N"
	condition:
		all of them
}