rule TTP_XOR_WriteProcessMemory_ffc6 {
  strings:
    $key_ffc6 = { a8 b4 [2] 9a 96 [2] 9c a3 [2] b2 a3 [2] 8d bf }

  condition:
    any of them
}