rule TTP_XOR_WriteProcessMemory_4d38 {
  strings:
    $key_4d38 = { 1a 4a [2] 28 68 [2] 2e 5d [2] 00 5d [2] 3f 41 }

  condition:
    any of them
}