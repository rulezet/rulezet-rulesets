import "pe"
rule RTPatch_software_update_package_data_file: PEiD
{
    strings:
        $a = { 4B 2A }
    condition:
        $a at pe.entry_point

}