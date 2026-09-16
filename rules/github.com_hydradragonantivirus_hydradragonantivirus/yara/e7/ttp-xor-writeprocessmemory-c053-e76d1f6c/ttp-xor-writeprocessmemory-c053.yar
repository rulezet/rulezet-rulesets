rule TTP_XOR_WriteProcessMemory_c053 {
  strings:
    $key_c053 = { 97 21 [2] a5 03 [2] a3 36 [2] 8d 36 [2] b2 2a }

  condition:
    any of them
}