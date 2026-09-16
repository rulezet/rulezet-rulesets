rule FSO_s_casus15_2 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		id = "d3f67fe9-a93f-504a-8b14-a815135d562f"
	strings:
		$s0 = "copy ( $dosya_gonder"
	condition:
		all of them
}