rule TTP_XOR_WriteProcessMemory_c4f4 {
  strings:
    $key_c4f4 = { 93 86 [2] a1 a4 [2] a7 91 [2] 89 91 [2] b6 8d }

  condition:
    any of them
}