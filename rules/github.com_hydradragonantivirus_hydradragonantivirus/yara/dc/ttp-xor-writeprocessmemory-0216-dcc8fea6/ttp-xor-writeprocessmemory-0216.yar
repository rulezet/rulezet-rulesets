rule TTP_XOR_WriteProcessMemory_0216 {
  strings:
    $key_0216 = { 55 64 [2] 67 46 [2] 61 73 [2] 4f 73 [2] 70 6f }

  condition:
    any of them
}