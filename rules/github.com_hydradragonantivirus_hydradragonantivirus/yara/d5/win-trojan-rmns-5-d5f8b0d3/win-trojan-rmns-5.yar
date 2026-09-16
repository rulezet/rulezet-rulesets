rule Win_Trojan_RMNS_5
{
strings:
	$a0 = { 840101f78a05a20001478b05a30101b8bd4bcd213db4bb }


condition:
	$a0
}