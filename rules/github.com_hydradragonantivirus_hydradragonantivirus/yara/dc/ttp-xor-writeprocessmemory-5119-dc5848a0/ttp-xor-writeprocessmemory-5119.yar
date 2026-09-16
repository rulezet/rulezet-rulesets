rule TTP_XOR_WriteProcessMemory_5119 {
  strings:
    $key_5119 = { 06 6b [2] 34 49 [2] 32 7c [2] 1c 7c [2] 23 60 }

  condition:
    any of them
}