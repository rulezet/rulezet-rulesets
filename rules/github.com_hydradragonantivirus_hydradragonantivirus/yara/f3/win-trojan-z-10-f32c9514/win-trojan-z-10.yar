rule Win_Trojan_Z_10
{
strings:
	$a0 = { 1401cd21eb04b43ecd21071f61c3b43fcd21c3b440cd21c3b80042cd21c38bf1e31ab90001 }


condition:
	$a0
}