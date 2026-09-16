rule TTP_XOR_WriteProcessMemory_4d68 {
  strings:
    $key_4d68 = { 1a 1a [2] 28 38 [2] 2e 0d [2] 00 0d [2] 3f 11 }

  condition:
    any of them
}