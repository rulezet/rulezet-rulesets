rule Win_Trojan_Agent_35408
{
strings:
	$a0 = { 558bec83ec585356578365dc00f3eb0c655850722d762e312e34 }

	$a1 = { 1d3e5e6063797979797e7e7e7e7e797979 }


condition:
	$a0 and $a1
}