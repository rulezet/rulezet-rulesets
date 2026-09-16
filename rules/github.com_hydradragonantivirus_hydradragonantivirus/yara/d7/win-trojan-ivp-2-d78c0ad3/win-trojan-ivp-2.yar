rule Win_Trojan_IVP_2
{
strings:
	$a0 = { 1101b94f008ab677012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}