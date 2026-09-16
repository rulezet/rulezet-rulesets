rule Win_Trojan_Packed_21
{
strings:
	$a0 = { bf4cf0410083c9ff33c06834f04100f2aef7d14951684cf04100e8110a000083 }


condition:
	$a0
}