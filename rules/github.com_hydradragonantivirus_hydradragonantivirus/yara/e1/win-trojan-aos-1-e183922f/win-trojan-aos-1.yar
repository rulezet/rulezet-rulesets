rule Win_Trojan_AOS_1
{
strings:
	$a0 = { 87cacfe8c4ff84c078305053069393b42fcd2126803fff9393750383c307268b4717929224 }


condition:
	$a0
}