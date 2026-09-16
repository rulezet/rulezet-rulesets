import "pe"
rule EXE_Manager_Version_30_1994_c_Solar_Designer_additional: PEiD
{
    strings:
        $a = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }
    condition:
        $a at pe.entry_point

}