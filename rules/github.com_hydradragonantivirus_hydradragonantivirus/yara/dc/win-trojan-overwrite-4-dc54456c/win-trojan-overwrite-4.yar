rule Win_Trojan_Overwrite_4
{
strings:
	$a0 = { 1c131e57bf82001e5768901231c050509aca0748009a91024800bf1c131e576a0068f4079a2b08 }


condition:
	$a0
}