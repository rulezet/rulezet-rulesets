import "pe"
rule FSG_v11_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
    condition:
        $a at pe.entry_point

}