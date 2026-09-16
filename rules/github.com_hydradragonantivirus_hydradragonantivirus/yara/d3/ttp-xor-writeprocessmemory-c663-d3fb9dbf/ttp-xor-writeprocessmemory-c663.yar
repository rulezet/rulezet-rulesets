rule TTP_XOR_WriteProcessMemory_c663 {
  strings:
    $key_c663 = { 91 11 [2] a3 33 [2] a5 06 [2] 8b 06 [2] b4 1a }

  condition:
    any of them
}