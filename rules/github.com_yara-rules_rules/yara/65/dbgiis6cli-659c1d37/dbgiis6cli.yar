rule dbgiis6cli {
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"
	condition:
		all of them
}