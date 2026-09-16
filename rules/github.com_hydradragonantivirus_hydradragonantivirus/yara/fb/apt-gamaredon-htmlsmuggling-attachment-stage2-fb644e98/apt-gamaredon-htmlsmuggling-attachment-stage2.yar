rule apt_GAMAREDON_HTMLSmuggling_Attachment_stage2 {
  meta:
    id             = "e82335ea-48d5-409c-a270-cfd5a2197c44"
    version        = "1.0"
    intrusion_set  = "Gamaredon"
    description    = "Detects Gamaredon HTMLSmuggling attachment"
    source         = "SEKOIA"
    creation_date  = "2023-01-20"
    classification = "TLP:WHITE"

  strings:
    $ = ") == -1) die();" ascii
    $ = "'data:application/x-rar-compressed;base64, ' +" ascii
    $ = ".appendChild(img);" ascii
    $ = "['Win32', 'Win64', 'Windows', 'WinCE'].indexOf(" ascii
    $ = " = navigator[\"platform\"];" ascii

  condition:
    4 of them and filesize < 1MB
}