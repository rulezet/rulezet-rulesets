rule TTP_XOR_WriteProcessMemory_1a28 {
  strings:
    $key_1a28 = { 4d 5a [2] 7f 78 [2] 79 4d [2] 57 4d [2] 68 51 }

  condition:
    any of them
}