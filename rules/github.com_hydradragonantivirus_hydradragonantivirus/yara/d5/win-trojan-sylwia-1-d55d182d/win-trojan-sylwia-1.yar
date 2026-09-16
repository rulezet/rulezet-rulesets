rule Win_Trojan_Sylwia_1
{
strings:
	$a0 = { 013d0f8674293d004b751f061e555756525153502e8916c3022e8c1ec502e81200585b595a5e5f5d1f072eff2ebf }


condition:
	$a0
}