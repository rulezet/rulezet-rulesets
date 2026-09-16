rule OBFUS_PowerShell_Execution {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "09.02.2022"
		description = "Detects some variations of obfuscated PowerShell code to execute further PowerShell code"

	strings:
		$a1 = "-nop -w hiddEn -Ep bypass -Enc" ascii nocase
		$a2 = "-noP -sta -w 1 -enc" ascii nocase
		
		$b1 = "SQBFAF"

	condition:
		filesize < 300KB 
		and $b1
		and 1 of ($a*) 
}