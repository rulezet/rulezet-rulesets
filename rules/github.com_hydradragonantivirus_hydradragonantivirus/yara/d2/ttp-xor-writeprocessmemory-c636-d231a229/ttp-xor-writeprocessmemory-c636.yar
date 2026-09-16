rule TTP_XOR_WriteProcessMemory_c636 {
  strings:
    $key_c636 = { 91 44 [2] a3 66 [2] a5 53 [2] 8b 53 [2] b4 4f }

  condition:
    any of them
}