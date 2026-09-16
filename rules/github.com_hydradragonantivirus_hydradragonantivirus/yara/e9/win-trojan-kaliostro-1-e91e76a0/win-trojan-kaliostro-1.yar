rule Win_Trojan_Kaliostro_1
{
strings:
	$a0 = { 1eb8fe99cd21bbfe99433bc37503e9b6008cd8488ec0268b1e030081ebc8001e07b44acd210e1fb840008ec0bf13 }


condition:
	$a0
}