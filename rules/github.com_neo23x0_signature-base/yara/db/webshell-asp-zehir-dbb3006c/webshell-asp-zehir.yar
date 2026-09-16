rule webshell_ASP_zehir {
	meta:
		description = "Web Shell - file zehir.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
	condition:
		all of them
}