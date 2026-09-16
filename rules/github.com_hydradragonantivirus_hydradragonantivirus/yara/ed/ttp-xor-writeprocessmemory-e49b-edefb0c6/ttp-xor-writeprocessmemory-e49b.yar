rule TTP_XOR_WriteProcessMemory_e49b {
  strings:
    $key_e49b = { b3 e9 [2] 81 cb [2] 87 fe [2] a9 fe [2] 96 e2 }

  condition:
    any of them
}