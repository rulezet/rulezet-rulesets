rule TTP_XOR_WriteProcessMemory_568b {
  strings:
    $key_568b = { 01 f9 [2] 33 db [2] 35 ee [2] 1b ee [2] 24 f2 }

  condition:
    any of them
}