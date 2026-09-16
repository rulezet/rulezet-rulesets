rule TTP_XOR_WriteProcessMemory_138b {
  strings:
    $key_138b = { 44 f9 [2] 76 db [2] 70 ee [2] 5e ee [2] 61 f2 }

  condition:
    any of them
}