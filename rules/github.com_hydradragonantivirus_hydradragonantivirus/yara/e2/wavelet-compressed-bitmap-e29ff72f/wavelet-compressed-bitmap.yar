import "pe"
rule _Wavelet_compressed_bitmap_
{
	meta:
		description = "Wavelet compressed bitmap"
	strings:
		$0 = {57 49}
	condition:
		$0 at pe.entry_point
}