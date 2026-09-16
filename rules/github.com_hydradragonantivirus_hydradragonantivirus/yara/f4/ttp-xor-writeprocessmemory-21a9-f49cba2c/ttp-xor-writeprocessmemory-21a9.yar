rule TTP_XOR_WriteProcessMemory_21a9 {
  strings:
    $key_21a9 = { 76 db [2] 44 f9 [2] 42 cc [2] 6c cc [2] 53 d0 }

  condition:
    any of them
}