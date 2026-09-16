rule Win_Trojan_Aircop_7
{
strings:
	$a0 = { c47db8e400a3b87db83101a3bc7dff }


condition:
	$a0
}