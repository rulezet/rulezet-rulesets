rule Win_Trojan_Babylonia_3
{
strings:
	$a0 = { 2b5e0c395e08730983eed8e2f12bdbeb03035e148bc35b595ec385c0741a3d0000200073133d }


condition:
	$a0
}