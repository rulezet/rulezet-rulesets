rule TTP_XOR_WriteProcessMemory_c0f5 {
  strings:
    $key_c0f5 = { 97 87 [2] a5 a5 [2] a3 90 [2] 8d 90 [2] b2 8c }

  condition:
    any of them
}