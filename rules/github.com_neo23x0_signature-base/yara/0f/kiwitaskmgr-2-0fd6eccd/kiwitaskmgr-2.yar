rule KiwiTaskmgr_2 {
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		id = "ea021257-8ced-5131-a00a-be014b4112fb"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}