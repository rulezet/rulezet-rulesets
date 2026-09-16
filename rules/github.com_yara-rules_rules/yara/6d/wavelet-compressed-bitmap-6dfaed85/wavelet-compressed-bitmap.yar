import "pe"
rule Wavelet_compressed_bitmap: PEiD
{
    strings:
        $a = { 57 49 }
    condition:
        $a at pe.entry_point

}