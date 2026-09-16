rule TTP_XOR_WriteProcessMemory_4758 {
  strings:
    $key_4758 = { 10 2a [2] 22 08 [2] 24 3d [2] 0a 3d [2] 35 21 }

  condition:
    any of them
}