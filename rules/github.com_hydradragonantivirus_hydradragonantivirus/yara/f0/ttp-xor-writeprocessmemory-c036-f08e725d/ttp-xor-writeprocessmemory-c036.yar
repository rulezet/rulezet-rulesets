rule TTP_XOR_WriteProcessMemory_c036 {
  strings:
    $key_c036 = { 97 44 [2] a5 66 [2] a3 53 [2] 8d 53 [2] b2 4f }

  condition:
    any of them
}