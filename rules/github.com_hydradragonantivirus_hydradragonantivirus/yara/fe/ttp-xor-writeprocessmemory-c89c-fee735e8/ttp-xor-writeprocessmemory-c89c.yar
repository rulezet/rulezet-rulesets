rule TTP_XOR_WriteProcessMemory_c89c {
  strings:
    $key_c89c = { 9f ee [2] ad cc [2] ab f9 [2] 85 f9 [2] ba e5 }

  condition:
    any of them
}