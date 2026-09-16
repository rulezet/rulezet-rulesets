rule Win_Trojan_Shine_1
{
strings:
	$a0 = { 8bb64a038dbe1101b91c01313583c702e2f9c3e8e9ffb9 }


condition:
	$a0
}