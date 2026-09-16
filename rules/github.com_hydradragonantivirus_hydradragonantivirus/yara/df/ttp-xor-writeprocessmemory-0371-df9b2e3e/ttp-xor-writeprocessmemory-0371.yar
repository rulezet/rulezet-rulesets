rule TTP_XOR_WriteProcessMemory_0371 {
  strings:
    $key_0371 = { 54 03 [2] 66 21 [2] 60 14 [2] 4e 14 [2] 71 08 }

  condition:
    any of them
}