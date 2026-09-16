rule Win_Trojan_Trivial_384
{
strings:
	$a0 = { 5b01b44e33c9ba5b01cd217249b42fcd21b8160003d8268a0724073c007506b44fcd21ebe8b8080003c38bd0b8013dcd21730ab44f33c9cd21721bebd08bd8 }


condition:
	$a0
}