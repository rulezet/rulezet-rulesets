rule TTP_XOR_WriteProcessMemory_6998 {
  strings:
    $key_6998 = { 3e ea [2] 0c c8 [2] 0a fd [2] 24 fd [2] 1b e1 }

  condition:
    any of them
}