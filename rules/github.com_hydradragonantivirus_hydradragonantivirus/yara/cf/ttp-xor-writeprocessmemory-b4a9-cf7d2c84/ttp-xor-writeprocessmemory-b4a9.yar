rule TTP_XOR_WriteProcessMemory_b4a9 {
  strings:
    $key_b4a9 = { e3 db [2] d1 f9 [2] d7 cc [2] f9 cc [2] c6 d0 }

  condition:
    any of them
}