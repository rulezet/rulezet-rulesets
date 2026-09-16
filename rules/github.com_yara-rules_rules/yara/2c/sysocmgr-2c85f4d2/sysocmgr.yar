rule sysocmgr
{
meta:
	author = "@patrickrolsen"
	reference = "System stand-alone Optional Component Manager - http://support.microsoft.com/kb/222444"
strings:
	$s1 = "SYSOCMGR.EXE" wide
	$s2 = "System stand-alone Optional Component Manager" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}