rule Win_Trojan_Ida_1
{
strings:
	$a0 = { 02d5d58854381bd46fad6b586333d46c54d0e4c154179086933722 }


condition:
	$a0
}