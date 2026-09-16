rule TTP_XOR_WriteProcessMemory_5509 {
  strings:
    $key_5509 = { 02 7b [2] 30 59 [2] 36 6c [2] 18 6c [2] 27 70 }

  condition:
    any of them
}