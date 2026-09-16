rule Win_Trojan_Anti_17
{
strings:
	$a0 = { 5d81ed09018db623018bfeb914028a260501fecc }


condition:
	$a0
}