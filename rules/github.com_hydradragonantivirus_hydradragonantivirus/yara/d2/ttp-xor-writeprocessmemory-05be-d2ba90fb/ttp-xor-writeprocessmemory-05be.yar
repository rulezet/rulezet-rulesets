rule TTP_XOR_WriteProcessMemory_05be {
  strings:
    $key_05be = { 52 cc [2] 60 ee [2] 66 db [2] 48 db [2] 77 c7 }

  condition:
    any of them
}