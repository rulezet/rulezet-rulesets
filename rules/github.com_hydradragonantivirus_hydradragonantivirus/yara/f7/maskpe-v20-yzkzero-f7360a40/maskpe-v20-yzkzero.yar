rule _MaskPE_V20__yzkzero_
{
	meta:
		description = "MaskPE V2.0 -> yzkzero"
	strings:
		$0 = {B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3}
	condition:
		$0
}