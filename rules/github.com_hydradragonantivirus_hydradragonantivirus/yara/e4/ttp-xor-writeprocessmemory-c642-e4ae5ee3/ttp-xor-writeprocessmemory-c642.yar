rule TTP_XOR_WriteProcessMemory_c642 {
  strings:
    $key_c642 = { 91 30 [2] a3 12 [2] a5 27 [2] 8b 27 [2] b4 3b }

  condition:
    any of them
}