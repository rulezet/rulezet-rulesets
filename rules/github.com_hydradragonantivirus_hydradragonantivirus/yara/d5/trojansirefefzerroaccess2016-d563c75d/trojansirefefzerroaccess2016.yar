rule TrojanSirefefZerroAccess2016
{
	meta:
		Description  = "Trojan.Sirefef.E.sm"
		ThreatLevel  = "5"

	strings:

		$ = "GoogleUpdate.exe" ascii wide
		$ = "%08x.@" ascii wide
		$ = "%08x.$" ascii wide
		$ = "%08x.~" ascii wide

		$s1 = "\\Google\\Desktop\\Install\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\\#." ascii wide
		$s2 = "\\BaseNamedObjects\\Restricted\\{12E9D947-EDF5-4191-AADB-F51815F004D8}" ascii wide
		$s3 = "\\BaseNamedObjects\\Restricted\\{889E2280-F15E-4330-A3F4-D4EEF899AAF6}" ascii wide
		$s4 = "\\BaseNamedObjects\\Restricted\\{1FD06E7A-B215-4ae2-B209-AC869A3DF0B7}" ascii wide
		$s5 = "\\BaseNamedObjects\\Restricted\\{A3D35150-6823-4462-8C6E-7417FF841D7A}" ascii wide
		$s6 = "80000000.@" ascii wide
		$s7 = "=cccctp=ddddt:=rrrrt<=sssst" ascii wide
		$s8 = "=ccccta=ddddt+=rrrrt-=sssst" ascii wide

	condition:
		(3 of them) or (any of ($s*))
}