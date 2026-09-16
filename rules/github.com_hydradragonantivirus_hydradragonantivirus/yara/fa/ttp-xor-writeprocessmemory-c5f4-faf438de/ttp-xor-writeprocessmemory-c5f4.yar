rule TTP_XOR_WriteProcessMemory_c5f4 {
  strings:
    $key_c5f4 = { 92 86 [2] a0 a4 [2] a6 91 [2] 88 91 [2] b7 8d }

  condition:
    any of them
}