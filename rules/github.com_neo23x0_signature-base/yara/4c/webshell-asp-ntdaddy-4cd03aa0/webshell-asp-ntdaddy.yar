rule webshell_asp_ntdaddy {
	meta:
		description = "Web Shell - file ntdaddy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 =  "if  FP  =  \"RefreshFolder\"  or  "
		$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
	condition:
		1 of them
}