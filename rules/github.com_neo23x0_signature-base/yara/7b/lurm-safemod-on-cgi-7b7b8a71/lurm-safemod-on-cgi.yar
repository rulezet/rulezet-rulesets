rule lurm_safemod_on_cgi {
	meta:
		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5ea4f901ce1abdf20870c214b3231db3"
		id = "74e77260-a547-5553-8430-2620f8549f50"
	strings:
		$s0 = "Network security team :: CGI Shell" fullword
		$s1 = "#########################<<KONEC>>#####################################" fullword
		$s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
	condition:
		1 of them
}