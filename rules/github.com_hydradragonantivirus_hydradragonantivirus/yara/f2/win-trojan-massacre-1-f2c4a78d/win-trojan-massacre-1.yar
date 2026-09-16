rule Win_Trojan_Massacre_1
{
strings:
	$a0 = { a3f2028916f002e871feb91c00baee02b440e876fe8b0e0c038b160e03b80157cd21b43ecd215a }


condition:
	$a0
}