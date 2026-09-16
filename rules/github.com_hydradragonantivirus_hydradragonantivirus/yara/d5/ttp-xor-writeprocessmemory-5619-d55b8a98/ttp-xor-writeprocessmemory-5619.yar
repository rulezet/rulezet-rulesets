rule TTP_XOR_WriteProcessMemory_5619 {
  strings:
    $key_5619 = { 01 6b [2] 33 49 [2] 35 7c [2] 1b 7c [2] 24 60 }

  condition:
    any of them
}