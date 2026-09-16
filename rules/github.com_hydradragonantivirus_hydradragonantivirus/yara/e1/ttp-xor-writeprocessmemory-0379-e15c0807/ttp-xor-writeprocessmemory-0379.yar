rule TTP_XOR_WriteProcessMemory_0379 {
  strings:
    $key_0379 = { 54 0b [2] 66 29 [2] 60 1c [2] 4e 1c [2] 71 00 }

  condition:
    any of them
}