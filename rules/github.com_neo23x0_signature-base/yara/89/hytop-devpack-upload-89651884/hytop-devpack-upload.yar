rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b09852bda534627949f0259828c967de"
		id = "43054993-b0dd-5d2e-9890-db1f47759be5"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}