rule TTP_XOR_WriteProcessMemory_02a9 {
  strings:
    $key_02a9 = { 55 db [2] 67 f9 [2] 61 cc [2] 4f cc [2] 70 d0 }

  condition:
    any of them
}