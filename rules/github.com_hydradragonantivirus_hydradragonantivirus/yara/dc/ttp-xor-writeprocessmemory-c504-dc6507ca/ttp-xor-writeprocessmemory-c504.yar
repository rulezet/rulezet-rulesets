rule TTP_XOR_WriteProcessMemory_c504 {
  strings:
    $key_c504 = { 92 76 [2] a0 54 [2] a6 61 [2] 88 61 [2] b7 7d }

  condition:
    any of them
}