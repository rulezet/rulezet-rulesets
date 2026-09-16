rule TTP_XOR_WriteProcessMemory_d2f4 {
  strings:
    $key_d2f4 = { 85 86 [2] b7 a4 [2] b1 91 [2] 9f 91 [2] a0 8d }

  condition:
    any of them
}