rule Win_Trojan_BO2K_50
{
strings:
	$a0 = { 558bec568b75[0-8]08803e00740346ebf88a46014684c0????????????3c4275056a01??eb403c537513464656 }


condition:
	$a0
}