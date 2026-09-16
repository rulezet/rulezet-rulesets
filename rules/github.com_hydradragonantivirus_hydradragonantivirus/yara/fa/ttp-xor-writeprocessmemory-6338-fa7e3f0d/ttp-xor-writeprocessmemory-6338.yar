rule TTP_XOR_WriteProcessMemory_6338 {
  strings:
    $key_6338 = { 34 4a [2] 06 68 [2] 00 5d [2] 2e 5d [2] 11 41 }

  condition:
    any of them
}