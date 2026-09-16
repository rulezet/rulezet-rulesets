rule js_powershell_usage
{
	meta:
		author = "k3rnelcallz"
		sha = "42aa8d13849dba889ff65c323b27d7b14a442909471b7f366b0512803e84c260"
		mod_date = "12-13-25"
		description = "Powershell objects usage with cleanup routine for payload"
		source = "mbazaar"
        tags = "Family: Rhadamanthys"

	strings:
		$s1 = "fromCharCode" nocase ascii wide
		$s2 = "Bypass" nocase ascii wide
		$s3 = "eval(String" nocase ascii wide
		$s4 = "Start-Sleep" nocase ascii wide
		$s5 = "ActiveXObject" ascii wide
		$s6 = "Invoke-Expression\x20(IrM" nocase wide
		$s7 = "['DeleteFile'](WScript['ScriptFullName'])" nocase ascii wide 
	condition: 
		($s1 or $s2 or $s3 or $s4 or $s5)
		and ($s6 and $s7)
}