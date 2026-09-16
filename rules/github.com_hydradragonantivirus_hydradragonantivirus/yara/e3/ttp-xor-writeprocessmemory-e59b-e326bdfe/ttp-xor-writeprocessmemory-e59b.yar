rule TTP_XOR_WriteProcessMemory_e59b {
  strings:
    $key_e59b = { b2 e9 [2] 80 cb [2] 86 fe [2] a8 fe [2] 97 e2 }

  condition:
    any of them
}