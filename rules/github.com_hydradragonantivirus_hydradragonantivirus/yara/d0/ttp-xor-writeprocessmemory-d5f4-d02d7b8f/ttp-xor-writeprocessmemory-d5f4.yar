rule TTP_XOR_WriteProcessMemory_d5f4 {
  strings:
    $key_d5f4 = { 82 86 [2] b0 a4 [2] b6 91 [2] 98 91 [2] a7 8d }

  condition:
    any of them
}