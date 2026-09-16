rule Win_Trojan_Bancos_692
{
strings:
	$a0 = { bb94ab15ce074fe857663a0a73d5f7c6bf512b31a7723a003cf77e39834f2bab88a790a4a69a94d4012ea11f50d6c6ece571d35c6a7e4ed51aa5ee4f5b26c3ce287f88d36233bc74f29715ac }


condition:
	$a0
}