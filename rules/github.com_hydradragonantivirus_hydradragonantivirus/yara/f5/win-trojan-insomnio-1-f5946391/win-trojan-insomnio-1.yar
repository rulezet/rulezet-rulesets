rule Win_Trojan_Insomnio_1
{
strings:
	$a0 = { 7cbb1204438b0748488907b106d3e08ec0b8f400bb4b0043890743438c07b99e01be007c33ff }


condition:
	$a0
}