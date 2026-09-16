rule TTP_XOR_WriteProcessMemory_1a30 {
  strings:
    $key_1a30 = { 4d 42 [2] 7f 60 [2] 79 55 [2] 57 55 [2] 68 49 }

  condition:
    any of them
}