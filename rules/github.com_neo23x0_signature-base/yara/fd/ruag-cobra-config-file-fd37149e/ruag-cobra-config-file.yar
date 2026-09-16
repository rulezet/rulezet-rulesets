rule RUAG_Cobra_Config_File {
  meta:
    description = "Detects a config text file used by malware Cobra in RUAG case"
    author = "Florian Roth (Nextron Systems)"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    id = "b3899d95-acc9-55ca-9025-edecce755ca6"
  strings:
    $h1 = "[NAME]" ascii

    $s1 = "object_id=" ascii
    $s2 = "[TIME]" ascii fullword
    $s3 = "lastconnect" ascii
    $s4 = "[CW_LOCAL]" ascii fullword
    $s5 = "system_pipe" ascii
    $s6 = "user_pipe" ascii
    $s7 = "[TRANSPORT]" ascii
    $s8 = "run_task_system" ascii
    $s9 = "[WORKDATA]" ascii
    $s10 = "address1" ascii
  condition:
    uint32(0) == 0x4d414e5b and $h1 at 0 and 8 of ($s*) and filesize < 5KB
}