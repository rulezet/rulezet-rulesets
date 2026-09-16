rule sig_20160829_4d25565eefc707ae328c2bf7868e8ce3 {
  meta:
    description = "datamaliciousorder - file 20160829_4d25565eefc707ae328c2bf7868e8ce3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81782e5e759690822d632d677d4b797d983591bcf09ad54ef19a49d205d30666"

  strings:
    $x1 = "name.ShellExecute(\"cMD.exe\", \"/c   ^po^wersh^ell.e^xe  -Exec^utionPo^licy bypa^ss -nop^rofi^le -wi^ndowst^yle hidden (New-Obj" ascii
    $x2 = "name.ShellExecute(\"cMD.exe\", \"/c   ^po^wersh^ell.e^xe  -Exec^utionPo^licy bypa^ss -nop^rofi^le -wi^ndowst^yle hidden (New-Obj" ascii
    $s3 = "var name = new ActiveXObject(\"shell.application\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}