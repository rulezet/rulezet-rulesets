rule Win_Trojan_Bancos_864
{
strings:
	$a0 = { b2f3e10f277717248b59f71ee8f1a50a147ec2e07382f4f863cfa51f815076e4872a4a6df32e4b8b0e89f5389f830a370dbbe423185b0b4f39aa114ad8a08c7771 }


condition:
	$a0
}