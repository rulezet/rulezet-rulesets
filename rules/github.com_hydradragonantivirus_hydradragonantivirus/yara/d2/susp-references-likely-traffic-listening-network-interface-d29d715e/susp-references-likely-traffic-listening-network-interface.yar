rule SUSP_References_Likely_Traffic_Listening_Network_Interface
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to Network-Interface that might get used for traffic sniffing"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "Network-Interface" nocase ascii wide
        $  = "Network Interface" nocase ascii wide
    condition:
        1 of them
}