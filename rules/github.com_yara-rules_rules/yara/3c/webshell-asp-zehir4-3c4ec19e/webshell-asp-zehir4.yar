rule webshell_ASP_zehir4 {
	meta:
		description = "Web Shell - file zehir4.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"
	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
	condition:
		all of them
}