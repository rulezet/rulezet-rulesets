rule TTP_XOR_WriteProcessMemory_0236 {
  strings:
    $key_0236 = { 55 44 [2] 67 66 [2] 61 53 [2] 4f 53 [2] 70 4f }

  condition:
    any of them
}