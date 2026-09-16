rule TTP_XOR_WriteProcessMemory_c404 {
  strings:
    $key_c404 = { 93 76 [2] a1 54 [2] a7 61 [2] 89 61 [2] b6 7d }

  condition:
    any of them
}