import "pe"
rule DAEMON_Protect_067_DAEMONUG: PEiD
{
    strings:
        $a = { 60 60 9C 8C C9 32 C9 E3 0C }
    condition:
        $a at pe.entry_point

}