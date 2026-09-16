rule TTP_XOR_WriteProcessMemory_5a41 {
  strings:
    $key_5a41 = { 0d 33 [2] 3f 11 [2] 39 24 [2] 17 24 [2] 28 38 }

  condition:
    any of them
}