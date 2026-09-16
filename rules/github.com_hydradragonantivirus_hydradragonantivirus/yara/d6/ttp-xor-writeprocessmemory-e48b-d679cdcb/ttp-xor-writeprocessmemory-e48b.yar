rule TTP_XOR_WriteProcessMemory_e48b {
  strings:
    $key_e48b = { b3 f9 [2] 81 db [2] 87 ee [2] a9 ee [2] 96 f2 }

  condition:
    any of them
}