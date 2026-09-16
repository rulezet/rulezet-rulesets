rule TTP_XOR_WriteProcessMemory_3c36 {
  strings:
    $key_3c36 = { 6b 44 [2] 59 66 [2] 5f 53 [2] 71 53 [2] 4e 4f }

  condition:
    any of them
}