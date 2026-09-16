rule TTP_XOR_WriteProcessMemory_7118 {
  strings:
    $key_7118 = { 26 6a [2] 14 48 [2] 12 7d [2] 3c 7d [2] 03 61 }

  condition:
    any of them
}