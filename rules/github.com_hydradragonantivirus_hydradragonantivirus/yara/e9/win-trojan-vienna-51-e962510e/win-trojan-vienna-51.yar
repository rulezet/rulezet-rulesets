rule Win_Trojan_Vienna_51
{
strings:
	$a0 = { 5649454e4e4167effff83003e2ff3ffffdbe }


condition:
	$a0
}