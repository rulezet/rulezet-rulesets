rule TTP_XOR_WriteProcessMemory_738b {
  strings:
    $key_738b = { 24 f9 [2] 16 db [2] 10 ee [2] 3e ee [2] 01 f2 }

  condition:
    any of them
}