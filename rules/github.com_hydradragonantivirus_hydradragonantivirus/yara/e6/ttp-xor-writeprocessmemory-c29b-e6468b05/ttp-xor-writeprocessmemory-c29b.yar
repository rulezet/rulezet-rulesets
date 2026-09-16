rule TTP_XOR_WriteProcessMemory_c29b {
  strings:
    $key_c29b = { 95 e9 [2] a7 cb [2] a1 fe [2] 8f fe [2] b0 e2 }

  condition:
    any of them
}