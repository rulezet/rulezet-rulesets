rule Win_Trojan_DieLamer_1
{
strings:
	$a0 = { 1e8cc88ed8bf2800a15004310583c702ba50043bfa72f4 }


condition:
	$a0
}