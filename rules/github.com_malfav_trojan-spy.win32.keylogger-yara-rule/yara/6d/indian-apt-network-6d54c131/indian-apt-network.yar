rule Indian_APT_Network{

	meta:
		Author = "Diyar Saadi"
		Date = "06/07/2024"
		Malware_Nationality = "India"
		Malware_MD5_Hash = "8C095479D9BEBA9ED56BB8D95861686D"

	strings:
		$a0 = "HTTP/1.1User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10"
		$a1 = "Content-Type: application/x-www-form-urlencoded"
		$a2 = "URLDownloadToFileA"
		$a3 = "bgre.kozow.com"
		$a4 = "Gfg786v6fcd6v8j09jg67f6/dolist.php"
		$a5 = "Gfg786v6fcd6v8j09jg67f6/revshll.php"
		$a6 = "Gfg786v6fcd6v8j09jg67f6/filedownload2.php"
		$pers = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

	condition:
		(5 of ($a*) or $pers)
		
}