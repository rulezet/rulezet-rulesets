rule Win_Trojan_Easy_3
{
strings:
	$a0 = { 3d41fb771e3dd2047219a32300b440b1c8e864ff720da15d00e85affb440b221e857ffb43e }


condition:
	$a0
}