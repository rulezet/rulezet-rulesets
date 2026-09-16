rule TTP_XOR_WriteProcessMemory_2568 {
  strings:
    $key_2568 = { 72 1a [2] 40 38 [2] 46 0d [2] 68 0d [2] 57 11 }

  condition:
    any of them
}