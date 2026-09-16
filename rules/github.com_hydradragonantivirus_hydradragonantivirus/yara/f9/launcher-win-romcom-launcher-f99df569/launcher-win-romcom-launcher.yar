rule launcher_win_romcom_launcher {
  meta:
    id             = "e8fa8239-a763-4be2-8f34-8e112e65b35e"
    version        = "1.0"
    description    = "Detect the launcher of RomCom malware"
    author         = "Sekoia.io"
    creation_date  = "2022-11-04"
    classification = "TLP:CLEAR"

  strings:
        $ = "C:\\Users\\123\\source\\repos\\ins_asi\\Win32\\Release\\setup.pdb"

  condition:
    uint16(0) == 0x5A4D and all of them
}