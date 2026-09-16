rule CN_Honker_Baidu_Extractor_Ver1_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Baidu_Extractor_Ver1.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1899f979360e96245d31082e7e96ccedbdbe1413"
		id = "94f3c3d8-aa68-5589-b26f-42315634ff30"
	strings:
		$s3 = "\\Users\\Admin" wide 
		$s11 = "soso.com" fullword wide
		$s12 = "baidu.com" fullword wide
		$s19 = "cmd /c ping " fullword wide 
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}