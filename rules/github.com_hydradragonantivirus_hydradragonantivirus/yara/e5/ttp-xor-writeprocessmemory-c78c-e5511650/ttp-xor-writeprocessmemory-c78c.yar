rule TTP_XOR_WriteProcessMemory_c78c {
  strings:
    $key_c78c = { 90 fe [2] a2 dc [2] a4 e9 [2] 8a e9 [2] b5 f5 }

  condition:
    any of them
}