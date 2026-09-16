rule Browser_Data_Grabber
{
    meta:
        description = "Detection patterns for the tool 'Browser Data Grabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser Data Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BrowserDataGrabber\.git/ nocase ascii wide
                        $string2 = /\\BrowserDataGrabber\.pdb/ nocase ascii wide
                        $string3 = /\\BrowserDataGrabber\\/ nocase ascii wide
                        $string4 = ">BrowserDataGrabber<" nocase ascii wide
                        $string5 = "1830c05bde7c4d7b795968d4e3c25ecb3dd98763662b1d85fd4abfbbf8e5b660" nocase ascii wide
                        $string6 = "1d389e53c658a3919dfcd0d1e3dd08c34a2e875eb1520ec0b9648e43e25eaabc" nocase ascii wide
                        $string7 = "8173d4d17cb728e6f2c5e2ce8124ce7eb0f459dc62085bcaab786abf1f6b37a7" nocase ascii wide
                        $string8 = "a9d6d8e1051e28d933a3979f20e8fd7eb85611d2014502d093aa879681bbbc26" nocase ascii wide
                        $string9 = /BrowserDataGrabber\.exe/ nocase ascii wide
                        $string10 = /BrowserDataGrabber\-master\.zip/ nocase ascii wide
                        $string11 = "f2691b74-129f-4ac2-a88a-db4b0f36b609" nocase ascii wide
                        $string12 = "n37sn4k3/BrowserDataGrabber" nocase ascii wide

    condition:
        any of them
}