rule TTP_XOR_WriteProcessMemory_c063 {
  strings:
    $key_c063 = { 97 11 [2] a5 33 [2] a3 06 [2] 8d 06 [2] b2 1a }

  condition:
    any of them
}