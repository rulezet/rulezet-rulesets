rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b09852bda534627949f0259828c967de"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}