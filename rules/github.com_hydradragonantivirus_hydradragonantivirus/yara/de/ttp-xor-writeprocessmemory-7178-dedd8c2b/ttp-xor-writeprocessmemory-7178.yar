rule TTP_XOR_WriteProcessMemory_7178 {
  strings:
    $key_7178 = { 26 0a [2] 14 28 [2] 12 1d [2] 3c 1d [2] 03 01 }

  condition:
    any of them
}