rule Win_Trojan_Rycho_1
{
strings:
	$a0 = { 89169c03a39e0333c933d2b80042cd218cc88ed8ba9601b92000b8003fcd21813e96014d5a74 }


condition:
	$a0
}