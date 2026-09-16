rule Win_Trojan_Companion_10
{
strings:
	$a0 = { b402b44a8bdcb104d3eb43cd21bb2c008b07a3a6018cc8a3aa01a3ae01a3b201ba9901bba601b8004bcd21fa8bd88c }


condition:
	$a0
}