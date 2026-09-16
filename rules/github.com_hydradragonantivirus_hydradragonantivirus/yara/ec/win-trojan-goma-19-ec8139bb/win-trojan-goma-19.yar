rule Win_Trojan_Goma_19
{
strings:
	$a0 = { 89867703b440b971028d960501cd21b800429933c9cd21b440b91b00418d967303cd21e92cffcd }


condition:
	$a0
}