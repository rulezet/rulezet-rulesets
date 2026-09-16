rule Win_Trojan_SillyOC_21
{
strings:
	$a0 = { 57cd218916a408890ea608ba0001b440b9a807cd21b801578b0ea6088b16a408cd21b43ecd21 }


condition:
	$a0
}