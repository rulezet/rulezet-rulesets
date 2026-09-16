rule TTP_XOR_WriteProcessMemory_3226 {
  strings:
    $key_3226 = { 65 54 [2] 57 76 [2] 51 43 [2] 7f 43 [2] 40 5f }

  condition:
    any of them
}