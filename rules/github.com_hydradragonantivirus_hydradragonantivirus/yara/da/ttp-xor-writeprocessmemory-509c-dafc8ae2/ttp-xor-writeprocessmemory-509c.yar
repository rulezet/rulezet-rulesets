rule TTP_XOR_WriteProcessMemory_509c {
  strings:
    $key_509c = { 07 ee [2] 35 cc [2] 33 f9 [2] 1d f9 [2] 22 e5 }

  condition:
    any of them
}