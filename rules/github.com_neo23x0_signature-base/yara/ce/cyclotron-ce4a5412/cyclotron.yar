rule cyclotron {
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
		id = "7099462b-2a72-56cd-8a50-27cd445eb9d2"
	strings:
		$s1 = "\\Device\\IDTProt" wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii  
		$s3 = "\\??\\slIDTProt" wide
		$s4 = "IoDeleteDevice" fullword ascii  
		$s5 = "IoCreateSymbolicLink" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 3KB and all of them
}