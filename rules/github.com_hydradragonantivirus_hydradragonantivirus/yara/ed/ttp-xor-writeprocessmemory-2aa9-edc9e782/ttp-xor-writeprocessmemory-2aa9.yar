rule TTP_XOR_WriteProcessMemory_2aa9 {
  strings:
    $key_2aa9 = { 7d db [2] 4f f9 [2] 49 cc [2] 67 cc [2] 58 d0 }

  condition:
    any of them
}