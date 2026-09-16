rule TTP_XOR_WriteProcessMemory_7478 {
  strings:
    $key_7478 = { 23 0a [2] 11 28 [2] 17 1d [2] 39 1d [2] 06 01 }

  condition:
    any of them
}