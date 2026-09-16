rule CN_Honker_Tuoku_script_oracle_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "865dd591b552787eda18ee0ab604509bae18c197"
		id = "b88a0faa-1616-5f1b-80dc-6e6a2f0cb671"
	strings:
		$s0 = "webshell" fullword ascii 
		$s1 = "Silic Group Hacker Army " fullword ascii
	condition:
		filesize < 3KB and all of them
}