import "pe"
rule JAR_Archive_additional: PEiD
{
    strings:
        $a = { 1A 4A 61 72 1B }
    condition:
        $a at pe.entry_point

}