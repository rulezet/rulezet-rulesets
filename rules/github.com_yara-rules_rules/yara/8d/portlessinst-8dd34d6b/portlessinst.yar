rule portlessinst {
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "74213856fc61475443a91cd84e2a6c2f"
	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"
	condition:
		all of them
}