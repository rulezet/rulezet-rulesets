rule Win_Trojan_Genesis_5
{
strings:
	$a0 = { 4474ebb800438d964902cd2172df5152b801435033c9cd }


condition:
	$a0
}