rule ms11080_withcmd {
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2022-12-21"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
		id = "fa5002ac-d6e6-543f-8020-43dfae689b3b"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}