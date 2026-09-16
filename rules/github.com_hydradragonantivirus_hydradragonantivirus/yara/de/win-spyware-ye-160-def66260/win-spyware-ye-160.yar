rule Win_Spyware_ye_160
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9d63a77cb8df8a3c660bb62040651d }


condition:
	$a0
}