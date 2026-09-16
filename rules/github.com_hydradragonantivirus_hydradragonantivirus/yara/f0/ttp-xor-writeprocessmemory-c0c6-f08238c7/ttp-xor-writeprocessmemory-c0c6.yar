rule TTP_XOR_WriteProcessMemory_c0c6 {
  strings:
    $key_c0c6 = { 97 b4 [2] a5 96 [2] a3 a3 [2] 8d a3 [2] b2 bf }

  condition:
    any of them
}