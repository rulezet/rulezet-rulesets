rule TTP_XOR_WriteProcessMemory_c0f6 {
  strings:
    $key_c0f6 = { 97 84 [2] a5 a6 [2] a3 93 [2] 8d 93 [2] b2 8f }

  condition:
    any of them
}