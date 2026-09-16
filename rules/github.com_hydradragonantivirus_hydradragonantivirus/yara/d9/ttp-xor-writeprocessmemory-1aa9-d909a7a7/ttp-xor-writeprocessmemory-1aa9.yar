rule TTP_XOR_WriteProcessMemory_1aa9 {
  strings:
    $key_1aa9 = { 4d db [2] 7f f9 [2] 79 cc [2] 57 cc [2] 68 d0 }

  condition:
    any of them
}