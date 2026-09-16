rule Win_Trojan__0169_0006_001_1
{
strings:
	$a0 = { c9b8004233d2cd21b440b90300ba7703cd21b801575a59cd21b43ecd21585a1f59cd215a1fb8 }


condition:
	$a0
}