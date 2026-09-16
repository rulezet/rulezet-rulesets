rule HYTop_DevPack_2005Red {
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
		id = "963effd9-f31d-5238-9419-b5dd11822e56"
	strings:
		$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
		$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
	condition:
		all of them
}