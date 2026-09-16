rule iam_iamdll {
	meta:
		description = "Auto-generated rule - file iamdll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
		id = "15e8ddac-af17-5509-b552-b4364af57c90"
	strings:
		$s0 = "LSASRV.DLL" fullword ascii 
		$s1 = "iamdll.dll" fullword ascii 
		$s2 = "ChangeCreds" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}