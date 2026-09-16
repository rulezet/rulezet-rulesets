rule TTP_XOR_WriteProcessMemory_3aa9 {
  strings:
    $key_3aa9 = { 6d db [2] 5f f9 [2] 59 cc [2] 77 cc [2] 48 d0 }

  condition:
    any of them
}