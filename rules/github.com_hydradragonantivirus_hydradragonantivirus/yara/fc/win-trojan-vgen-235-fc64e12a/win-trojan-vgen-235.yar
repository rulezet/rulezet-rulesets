rule Win_Trojan_VGEN_235
{
strings:
	$a0 = { b82c012e8137601243434875f68812604fe1ff7613e1ee21561419eda4ce13df126145c4f9710c661c7f1c679f }


condition:
	$a0
}