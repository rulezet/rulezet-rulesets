rule webshell_php_fbi {
	meta:
		description = "Web Shell - file fbi.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1fb32f8e58c8deb168c06297a04a21f1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
	condition:
		all of them
}