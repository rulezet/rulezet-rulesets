rule Win_Trojan_VGEN_138
{
strings:
	$a0 = { 90905d81ed0601e84a16bdf115448f47311095e3bbbabbabb1abb0478468fd6663f32aca66c7fd6689443016d8dc }


condition:
	$a0
}