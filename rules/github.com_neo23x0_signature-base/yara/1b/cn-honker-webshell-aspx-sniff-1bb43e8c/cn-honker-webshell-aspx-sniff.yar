rule CN_Honker_Webshell_ASPX_sniff {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e246256696be90189e6d50a4ebc880e6d9e28dfd"
		id = "8cf47d71-1b97-5967-ad70-2ea6fad7cc29"
	strings:
		$s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii 
		$s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii 
	condition:
		filesize < 91KB and all of them
}