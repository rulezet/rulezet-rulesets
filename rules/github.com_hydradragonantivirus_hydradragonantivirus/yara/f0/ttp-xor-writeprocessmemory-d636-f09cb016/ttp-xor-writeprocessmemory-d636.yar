rule TTP_XOR_WriteProcessMemory_d636 {
  strings:
    $key_d636 = { 81 44 [2] b3 66 [2] b5 53 [2] 9b 53 [2] a4 4f }

  condition:
    any of them
}