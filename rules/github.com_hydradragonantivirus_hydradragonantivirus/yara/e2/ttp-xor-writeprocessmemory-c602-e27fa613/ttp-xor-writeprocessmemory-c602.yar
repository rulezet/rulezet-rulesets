rule TTP_XOR_WriteProcessMemory_c602 {
  strings:
    $key_c602 = { 91 70 [2] a3 52 [2] a5 67 [2] 8b 67 [2] b4 7b }

  condition:
    any of them
}