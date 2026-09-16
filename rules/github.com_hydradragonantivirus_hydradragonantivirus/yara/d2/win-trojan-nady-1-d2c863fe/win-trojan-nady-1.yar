rule Win_Trojan_Nady_1
{
strings:
	$a0 = { e8d3ffe9f500b440b905008d969d03cd218db66c028bfeacfec0aae85b00b440b9e801908d96 }


condition:
	$a0
}