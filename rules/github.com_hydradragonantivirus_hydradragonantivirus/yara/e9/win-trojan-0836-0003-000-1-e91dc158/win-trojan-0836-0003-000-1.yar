rule Win_Trojan__0836_0003_000_1
{
strings:
	$a0 = { 3e4d010f74208cc88ed8b44033d2b96101cd2133c933d2b80042cd21b440ba4e01b90400cd21b4 }


condition:
	$a0
}