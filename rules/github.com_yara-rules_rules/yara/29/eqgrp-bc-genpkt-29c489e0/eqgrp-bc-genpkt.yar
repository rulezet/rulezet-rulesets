rule EQGRP_bc_genpkt 
{

    meta:
        description = "Detects tool from EQGRP toolset - file bc-genpkt"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $x1 = "load auxiliary object=%s requested by file=%s" fullword ascii
        $x2 = "size of new packet, should be %d <= size <= %d bytes" fullword ascii
        $x3 = "verbosity - show lengths, packet dumps, etc" fullword ascii
        $s1 = "%s: error while loading shared libraries: %s%s%s%s%s" fullword ascii
        $s2 = "cannot dynamically load executable" fullword ascii
        $s3 = "binding file %s to %s: %s symbol `%s' [%s]" fullword ascii
        $s4 = "randomize the initiator cookie" fullword ascii
    
    condition:
        uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($s*) and 3 of them )
}