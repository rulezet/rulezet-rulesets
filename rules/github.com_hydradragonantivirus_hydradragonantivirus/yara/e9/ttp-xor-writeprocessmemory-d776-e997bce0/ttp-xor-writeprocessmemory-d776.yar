rule TTP_XOR_WriteProcessMemory_d776 {
  strings:
    $key_d776 = { 80 04 [2] b2 26 [2] b4 13 [2] 9a 13 [2] a5 0f }

  condition:
    any of them
}