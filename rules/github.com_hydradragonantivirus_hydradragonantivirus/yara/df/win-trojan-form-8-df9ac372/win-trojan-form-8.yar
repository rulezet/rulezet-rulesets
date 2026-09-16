rule Win_Trojan_Form_8
{
strings:
	$a0 = { 33c08ed0bcfe7bfb1e56525007b8c0078ed833f68b3e550026836d0302268b4503b106d3e033ff8ec0b9ff00fcf3a5 }


condition:
	$a0
}