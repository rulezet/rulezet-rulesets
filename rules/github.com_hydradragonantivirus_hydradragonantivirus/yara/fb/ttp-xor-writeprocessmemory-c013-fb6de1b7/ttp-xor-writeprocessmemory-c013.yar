rule TTP_XOR_WriteProcessMemory_c013 {
  strings:
    $key_c013 = { 97 61 [2] a5 43 [2] a3 76 [2] 8d 76 [2] b2 6a }

  condition:
    any of them
}