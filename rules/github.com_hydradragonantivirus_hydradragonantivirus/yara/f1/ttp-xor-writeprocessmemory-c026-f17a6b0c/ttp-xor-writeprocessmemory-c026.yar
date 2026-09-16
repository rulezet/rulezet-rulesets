rule TTP_XOR_WriteProcessMemory_c026 {
  strings:
    $key_c026 = { 97 54 [2] a5 76 [2] a3 43 [2] 8d 43 [2] b2 5f }

  condition:
    any of them
}