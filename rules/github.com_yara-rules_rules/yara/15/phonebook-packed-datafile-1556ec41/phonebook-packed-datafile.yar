import "pe"
rule Phonebook_packed_datafile: PEiD
{
    strings:
        $a = { 21 50 48 32 50 41 43 4B 24 }
    condition:
        $a at pe.entry_point

}