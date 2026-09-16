rule Win_Trojan_Resvir_1
{
strings:
	$a0 = { 4605b440b959038bd5ccb8004233c933d2ccb440b903008d5604cc5a59b8015780c91fcce90100 }


condition:
	$a0
}