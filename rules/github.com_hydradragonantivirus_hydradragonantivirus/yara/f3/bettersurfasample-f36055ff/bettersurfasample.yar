rule BetterSurfASample
{
    meta:
        Description = "Adware.BetterSurf.A.vb"
        ThreatLevel = "5"

    strings:
        $n1 = "Media Buzz" ascii wide
        $n2 = "MediaBuzz" ascii wide

                
    condition:
       all of ($n*)
}