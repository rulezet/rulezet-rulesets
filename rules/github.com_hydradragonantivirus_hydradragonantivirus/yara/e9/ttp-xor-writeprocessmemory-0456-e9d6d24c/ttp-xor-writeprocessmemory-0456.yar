rule TTP_XOR_WriteProcessMemory_0456 {
  strings:
    $key_0456 = { 53 24 [2] 61 06 [2] 67 33 [2] 49 33 [2] 76 2f }

  condition:
    any of them
}