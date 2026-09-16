rule TTP_XOR_WriteProcessMemory_c524 {
  strings:
    $key_c524 = { 92 56 [2] a0 74 [2] a6 41 [2] 88 41 [2] b7 5d }

  condition:
    any of them
}