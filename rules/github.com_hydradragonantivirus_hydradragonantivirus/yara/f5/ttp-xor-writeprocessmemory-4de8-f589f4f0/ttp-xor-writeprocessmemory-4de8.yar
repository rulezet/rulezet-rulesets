rule TTP_XOR_WriteProcessMemory_4de8 {
  strings:
    $key_4de8 = { 1a 9a [2] 28 b8 [2] 2e 8d [2] 00 8d [2] 3f 91 }

  condition:
    any of them
}