rule TTP_XOR_WriteProcessMemory_5a36 {
  strings:
    $key_5a36 = { 0d 44 [2] 3f 66 [2] 39 53 [2] 17 53 [2] 28 4f }

  condition:
    any of them
}