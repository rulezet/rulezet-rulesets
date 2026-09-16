rule TTP_XOR_WriteProcessMemory_c2f4 {
  strings:
    $key_c2f4 = { 95 86 [2] a7 a4 [2] a1 91 [2] 8f 91 [2] b0 8d }

  condition:
    any of them
}