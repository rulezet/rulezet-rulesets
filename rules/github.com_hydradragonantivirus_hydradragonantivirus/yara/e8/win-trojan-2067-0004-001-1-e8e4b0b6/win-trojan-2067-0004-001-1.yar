rule Win_Trojan__2067_0004_001_1
{
strings:
	$a0 = { 33c933d2b80042cd21b91a00b440ba2304cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}