rule TTP_XOR_WriteProcessMemory_48dd {
  strings:
    $key_48dd = { 1f af [2] 2d 8d [2] 2b b8 [2] 05 b8 [2] 3a a4 }

  condition:
    any of them
}