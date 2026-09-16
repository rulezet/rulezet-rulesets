rule thelast_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cceff6dc247aaa25512bad22120a14b4"
		id = "41310217-b9a7-5360-80c4-7d0a3969f848"
	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
	condition:
		all of them
}