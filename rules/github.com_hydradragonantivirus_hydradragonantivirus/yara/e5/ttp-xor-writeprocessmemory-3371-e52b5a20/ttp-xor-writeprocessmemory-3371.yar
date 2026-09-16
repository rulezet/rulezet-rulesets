rule TTP_XOR_WriteProcessMemory_3371 {
  strings:
    $key_3371 = { 64 03 [2] 56 21 [2] 50 14 [2] 7e 14 [2] 41 08 }

  condition:
    any of them
}