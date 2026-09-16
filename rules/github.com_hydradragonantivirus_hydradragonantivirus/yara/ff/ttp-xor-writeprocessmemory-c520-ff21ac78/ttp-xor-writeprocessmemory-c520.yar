rule TTP_XOR_WriteProcessMemory_c520 {
  strings:
    $key_c520 = { 92 52 [2] a0 70 [2] a6 45 [2] 88 45 [2] b7 59 }

  condition:
    any of them
}