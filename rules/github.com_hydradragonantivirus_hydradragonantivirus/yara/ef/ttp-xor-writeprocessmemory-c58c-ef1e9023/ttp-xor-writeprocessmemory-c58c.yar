rule TTP_XOR_WriteProcessMemory_c58c {
  strings:
    $key_c58c = { 92 fe [2] a0 dc [2] a6 e9 [2] 88 e9 [2] b7 f5 }

  condition:
    any of them
}