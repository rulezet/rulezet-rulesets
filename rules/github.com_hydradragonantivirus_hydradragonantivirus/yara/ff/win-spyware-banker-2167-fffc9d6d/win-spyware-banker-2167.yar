rule Win_Spyware_Banker_2167
{
strings:
	$a0 = { 8c9bc3c99703fe1067958c0ecdaa021327fd2392e3a42b45f3c816444893ec860e46c16fc8b340392b7c9a76bd6df47144f71f4fc9a1a0b13cf48ebaa0a6ae151aebb6aafd2394c8b36540d03f13 }


condition:
	$a0
}