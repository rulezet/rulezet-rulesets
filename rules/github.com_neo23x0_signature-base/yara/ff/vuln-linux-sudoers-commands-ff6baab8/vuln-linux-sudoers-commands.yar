rule VULN_Linux_Sudoers_Commands {
	meta:
		description = "Detects sudoers config with commands which might allow privilege escalation to root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		reference = "https://gtfobins.github.io/"
		date = "2022-11-22"
		modified = "2024-04-15"
		score = 50
		id = "221d90c8-e70e-5214-a03b-57ecabcdd480"
	strings:
		$command1 = "/sh " ascii
		$command2 = "/bash " ascii
		$command3 = "/ksh " ascii
		$command4 = "/csh " ascii
		$command5 = "/tcpdump " ascii
						$command8 = "/nano " ascii
		$command9 = "/pico " ascii
		$command10 = "/rview " ascii
		$command11 = "/vi " ascii
		$command12 = "/vim " ascii
		$command13 = "/rvi " ascii
		$command14 = "/rvim " ascii
				$command16 = "/less " ascii
		$command17 = "/dd " ascii
		 

	condition:
		( filename == "sudoers" or filepath contains "/etc/sudoers.d" ) and 
		any of ($command*)
}