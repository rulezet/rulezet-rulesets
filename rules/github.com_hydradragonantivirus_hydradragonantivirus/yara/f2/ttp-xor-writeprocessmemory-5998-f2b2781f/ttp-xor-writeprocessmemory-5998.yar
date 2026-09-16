rule TTP_XOR_WriteProcessMemory_5998 {
  strings:
    $key_5998 = { 0e ea [2] 3c c8 [2] 3a fd [2] 14 fd [2] 2b e1 }

  condition:
    any of them
}