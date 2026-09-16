rule Win_Trojan_Stoned_25
{
strings:
	$a0 = { 0500518bc68b0ec200cd1359730733c0cd13e2eef9c3558bec9cf746fe000175559d5d }


condition:
	$a0
}