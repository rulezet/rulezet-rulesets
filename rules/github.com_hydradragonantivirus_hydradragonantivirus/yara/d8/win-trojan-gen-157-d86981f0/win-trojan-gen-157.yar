rule Win_Trojan_Gen_157
{
strings:
	$a0 = { 7f009aee0131005589e581ec0001e8e6fd9af10062008dbe00ff1657bf3e001e57e819fdbfc7020e579a290162 }


condition:
	$a0
}