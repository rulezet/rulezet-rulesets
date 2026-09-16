rule Win_Trojan_Manzon_4
{
strings:
	$a0 = { b97c05ba00019c0ee83100be0001b97c05b8e506ffd046e2f8b86a06ffd08b1edd06e5408ed8250f008bc8b4402e }


condition:
	$a0
}