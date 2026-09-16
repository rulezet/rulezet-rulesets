rule TTP_XOR_WriteProcessMemory_05a9 {
  strings:
    $key_05a9 = { 52 db [2] 60 f9 [2] 66 cc [2] 48 cc [2] 77 d0 }

  condition:
    any of them
}