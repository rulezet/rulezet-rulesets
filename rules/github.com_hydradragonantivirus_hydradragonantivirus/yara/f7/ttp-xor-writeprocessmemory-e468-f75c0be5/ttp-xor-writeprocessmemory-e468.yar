rule TTP_XOR_WriteProcessMemory_e468 {
  strings:
    $key_e468 = { b3 1a [2] 81 38 [2] 87 0d [2] a9 0d [2] 96 11 }

  condition:
    any of them
}