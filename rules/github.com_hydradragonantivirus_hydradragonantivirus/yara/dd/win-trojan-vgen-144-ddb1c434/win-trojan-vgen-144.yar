rule Win_Trojan_Vgen_144
{
strings:
	$a0 = { c08ec033ff268b16ae00268b0ea2003bd1740c268b0eb2003bd17403b403c383fd01742683fd02740c268b1e8400 }


condition:
	$a0
}