rule TTP_XOR_WriteProcessMemory_609c {
  strings:
    $key_609c = { 37 ee [2] 05 cc [2] 03 f9 [2] 2d f9 [2] 12 e5 }

  condition:
    any of them
}