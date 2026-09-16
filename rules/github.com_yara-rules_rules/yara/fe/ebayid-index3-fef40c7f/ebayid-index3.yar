rule eBayId_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0412b1e37f41ea0d002e4ed11608905f"
	strings:
		$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
	condition:
		all of them
}