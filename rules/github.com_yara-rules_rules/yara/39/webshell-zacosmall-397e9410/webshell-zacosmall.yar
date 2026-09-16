rule webshell_zacosmall {
	meta:
		description = "Web Shell - file zacosmall.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
	condition:
		all of them
}