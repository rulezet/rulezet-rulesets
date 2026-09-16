rule TTP_XOR_WriteProcessMemory_1748 {
  strings:
    $key_1748 = { 40 3a [2] 72 18 [2] 74 2d [2] 5a 2d [2] 65 31 }

  condition:
    any of them
}