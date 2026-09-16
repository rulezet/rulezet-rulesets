rule CN_Tools_MyUPnP {
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
		id = "394e19d3-882e-5a7c-a3a0-e662bd67955c"
	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}