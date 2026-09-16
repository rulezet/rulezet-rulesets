rule Win_Trojan_Crypt_210
{
strings:
	$a0 = { 558bec83c4f0535657b874944100e801bcfeffe834f0ffff33c055682ea3410064ff30648920a100f3 }


condition:
	$a0
}