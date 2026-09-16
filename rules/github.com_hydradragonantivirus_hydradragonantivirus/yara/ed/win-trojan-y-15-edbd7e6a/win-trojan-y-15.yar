rule Win_Trojan_Y_15
{
strings:
	$a0 = { 434fabb04daab8006cbb0100ba1000beb603b121e89f01720fb74093b9b20399e89301b43ee88e }


condition:
	$a0
}