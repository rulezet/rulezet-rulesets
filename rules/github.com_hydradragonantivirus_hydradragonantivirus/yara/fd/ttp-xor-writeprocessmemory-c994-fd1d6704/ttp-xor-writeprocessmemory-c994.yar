rule TTP_XOR_WriteProcessMemory_c994 {
  strings:
    $key_c994 = { 9e e6 [2] ac c4 [2] aa f1 [2] 84 f1 [2] bb ed }

  condition:
    any of them
}