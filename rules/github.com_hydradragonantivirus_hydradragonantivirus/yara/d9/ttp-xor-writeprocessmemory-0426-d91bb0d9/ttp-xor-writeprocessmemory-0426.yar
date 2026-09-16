rule TTP_XOR_WriteProcessMemory_0426 {
  strings:
    $key_0426 = { 53 54 [2] 61 76 [2] 67 43 [2] 49 43 [2] 76 5f }

  condition:
    any of them
}