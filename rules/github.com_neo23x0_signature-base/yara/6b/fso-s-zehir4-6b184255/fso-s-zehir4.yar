rule FSO_s_zehir4 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		id = "9f1adcd6-b721-54ef-a20f-c3a353629a40"
	strings:
		$s5 = " byMesaj "
	condition:
		all of them
}