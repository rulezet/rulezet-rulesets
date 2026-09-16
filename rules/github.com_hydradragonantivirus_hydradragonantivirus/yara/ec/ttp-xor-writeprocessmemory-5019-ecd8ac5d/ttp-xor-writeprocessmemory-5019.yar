rule TTP_XOR_WriteProcessMemory_5019 {
  strings:
    $key_5019 = { 07 6b [2] 35 49 [2] 33 7c [2] 1d 7c [2] 22 60 }

  condition:
    any of them
}