rule Win_Trojan_Sojourn_1
{
strings:
	$a0 = { 8ed08ed8e80500b8004ccd21582d09018be889aed402b8edaccd213bc8741be822011e668b9e79022bc08ed86689 }


condition:
	$a0
}