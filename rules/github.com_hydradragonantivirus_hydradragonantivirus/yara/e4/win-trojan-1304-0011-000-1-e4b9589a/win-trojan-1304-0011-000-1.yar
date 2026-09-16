rule Win_Trojan__1304_0011_000_1
{
strings:
	$a0 = { c3e846005b5f07b440b9da0590ba3307cd21c3268b450f80fc64c38d96ee061e0e1fb43cb903 }


condition:
	$a0
}