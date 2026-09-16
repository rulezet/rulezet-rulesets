rule Win_Trojan_Quevedo_3
{
strings:
	$a0 = { b80325cd21071fb8023dba7d02cd21720f93b92a00ba9002b440cd21b42ecd21b42acd2180 }


condition:
	$a0
}