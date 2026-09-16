rule Win_Trojan_Bhorse_2
{
strings:
	$a0 = { 8ed8bd007cfa8ed08be5fb5055a11304ff364e00ff364c002e8f06727d2e8f06747d48a31304b106d3e08ec0c7 }


condition:
	$a0
}