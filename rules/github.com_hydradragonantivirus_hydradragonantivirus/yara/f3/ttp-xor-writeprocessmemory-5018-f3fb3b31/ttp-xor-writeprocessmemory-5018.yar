rule TTP_XOR_WriteProcessMemory_5018 {
  strings:
    $key_5018 = { 07 6a [2] 35 48 [2] 33 7d [2] 1d 7d [2] 22 61 }

  condition:
    any of them
}