rule sig_2edb9e91d43f669148c004e0faed8c3a {
	meta:
		description = "Auto-generated rule - file 2edb9e91d43f669148c004e0faed8c3a"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "0e15715b82f4d59a376c9e5e5842d43fae01fdf4408e3453a4b1771bb80c9159"
	strings:
		$s1 = "Toe.exe" fullword wide 
		$s2 = "System.Web.UI.WebControls.WebParts" fullword ascii 
		$s3 = "Selenology Protactinium Slapper" fullword wide 
		$s4 = "x:\\kEZ" fullword ascii 
		$s5 = "uJGRaoEzf.Properties.Resources.resources" fullword ascii 
		$s6 = "get_IcfXzSYMdZCj" fullword ascii 
		$s7 = "uJGRaoEzf.Properties.Resources" fullword wide 
		$s8 = "iFhosTkhl" fullword ascii 
		$s9 = "AsyncCompletedEventHandler" fullword ascii 
		$s10 = "Tonsillitis Prevalence Inc Sextants Recliner" fullword wide 
		$s11 = ",Tonsillitis Prevalence Inc Sextants Recliner" fullword ascii 
		$s12 = "uJGRaoEzf.Properties" fullword ascii 
		$s13 = "1.6.6.4" fullword wide 
		$s14 = "Selenology Protactinium Slapper" fullword ascii 
		$s15 = "5.1.8.9" fullword wide 
		$s16 = "uJGRaoEzf.Resources" fullword ascii 
		$s17 = "lfzotn" fullword ascii 
		$s18 = "MemoryFailPoint" fullword ascii 
		$s19 = "EncoderFallbackException" fullword ascii 
		$s20 = "HasCopySemanticsAttribute" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}