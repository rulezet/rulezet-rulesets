rule TTP_XOR_WriteProcessMemory_c6f5 {
  strings:
    $key_c6f5 = { 91 87 [2] a3 a5 [2] a5 90 [2] 8b 90 [2] b4 8c }

  condition:
    any of them
}