rule TTP_XOR_WriteProcessMemory_2b66 {
  strings:
    $key_2b66 = { 7c 14 [2] 4e 36 [2] 48 03 [2] 66 03 [2] 59 1f }

  condition:
    any of them
}