rule genhash_genhash {
	meta:
		description = "Auto-generated rule - file genhash.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
		id = "bec3c014-df3b-5ac0-9501-9b648856e02b"
	strings:
		$s1 = "genhash.exe <password>" fullword ascii  
		$s3 = "Password: %s" fullword ascii  
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii 
		$s5 = "This tool generates LM and NT hashes." fullword ascii 
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}