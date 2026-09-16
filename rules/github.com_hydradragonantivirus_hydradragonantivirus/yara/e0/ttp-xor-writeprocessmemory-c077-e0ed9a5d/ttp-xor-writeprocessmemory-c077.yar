rule TTP_XOR_WriteProcessMemory_c077 {
  strings:
    $key_c077 = { 97 05 [2] a5 27 [2] a3 12 [2] 8d 12 [2] b2 0e }

  condition:
    any of them
}