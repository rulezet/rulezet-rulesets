rule apt_queueseed {
  meta:
    id             = "35f7ffd5-4f6f-4b31-8d60-c713a15d14e8"
    version        = "1.0"
    description    = "Detects strings of Queueseed/Kapeka malware"
    author         = "Sekoia.io"
    creation_date  = "2024-04-22"
    classification = "TLP:CLEAR"

  strings:
        $ = { 2D 00 6F 00 00 00 }      $ = { 2D 00 62 00 63 00 00 00 }      $ = { 20 00 00 00 00 00 00 00 }      $ = { 20 00 2D 00 77 00 00 00 }      $ = { 35 00 3A 00 20 00 00 00 }      $ = { 34 00 3A 00 20 00 00 00 }      $ = { 33 00 3A 00 20 00 00 00 }      $ = { 32 00 3A 00 20 00 00 00 }      $ = { 31 00 3A 00 20 00 00 00 }      $ = { 50 00 49 00 44 00 20 00 3A 00 20 00 00 00 00 00 }  
    $ = "ExitCode : " wide

  condition:
    uint16be(0) == 0x4d5a and all of them and filesize < 200KB
}