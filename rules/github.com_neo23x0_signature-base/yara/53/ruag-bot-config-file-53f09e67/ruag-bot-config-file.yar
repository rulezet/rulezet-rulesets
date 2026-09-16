rule RUAG_Bot_Config_File {
  meta:
    description = "Detects a specific config file used by malware in RUAG APT case"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "aa3d5f9e-0b23-5180-9e52-a7d705712747"
  strings:
    $s1 = "[CONFIG]" ascii
    $s2 = "name = " ascii
    $s3 = "exe = cmd.exe" ascii
  condition:
    uint32(0) == 0x4e4f435b and $s1 at 0 and $s2 and $s3 and filesize < 160
}