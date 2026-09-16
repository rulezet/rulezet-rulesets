rule Win_Trojan_Intruder_11
{
strings:
	$a0 = { 8cc88ed88cc0a30400e86902e826007509e88c02e8ee00e8c902e8710258bb0200fa8ed3bc00008e0604008e1e0400 }


condition:
	$a0
}