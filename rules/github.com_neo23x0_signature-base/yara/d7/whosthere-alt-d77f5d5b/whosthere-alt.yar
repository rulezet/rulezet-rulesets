rule whosthere_alt {
	meta:
		description = "Auto-generated rule - file whosthere-alt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
		id = "92e98381-9142-58af-82ce-4df9eb0a0039"
	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii  
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii  
		$s2 = "dump output to a file, -o filename" fullword ascii  
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii  
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii 
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii  
		$s6 = ".\\pth.dll" fullword ascii 
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and 2 of them
}