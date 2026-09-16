rule dll_PacketX {
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		score = 50
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
		id = "19ab5977-934d-5e3f-8bba-925bb57bf486"
	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}