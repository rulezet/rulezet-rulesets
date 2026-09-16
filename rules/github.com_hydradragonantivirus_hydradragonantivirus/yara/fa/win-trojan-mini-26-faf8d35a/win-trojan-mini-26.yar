rule Win_Trojan_Mini_26
{
strings:
	$a0 = { 069090b44febceb8024233c933d2cd212d030097b440508bd552b98b0090cd21b8004233 }


condition:
	$a0
}