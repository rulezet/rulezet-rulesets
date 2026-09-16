rule TTP_XOR_WriteProcessMemory_0a36 {
  strings:
    $key_0a36 = { 5d 44 [2] 6f 66 [2] 69 53 [2] 47 53 [2] 78 4f }

  condition:
    any of them
}