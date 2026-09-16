rule Win_Trojan_Vienna_90
{
strings:
	$a0 = { fd6518cb95c4c15729ea68eb74afa5fb95c952099654ed93a5b96ff6ae27 }


condition:
	$a0
}