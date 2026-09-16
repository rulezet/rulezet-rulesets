rule TTP_XOR_WriteProcessMemory_c19b {
  strings:
    $key_c19b = { 96 e9 [2] a4 cb [2] a2 fe [2] 8c fe [2] b3 e2 }

  condition:
    any of them
}