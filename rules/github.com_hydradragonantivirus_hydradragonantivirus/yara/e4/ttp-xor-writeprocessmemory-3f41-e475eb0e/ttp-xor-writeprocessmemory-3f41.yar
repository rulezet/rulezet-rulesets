rule TTP_XOR_WriteProcessMemory_3f41 {
  strings:
    $key_3f41 = { 68 33 [2] 5a 11 [2] 5c 24 [2] 72 24 [2] 4d 38 }

  condition:
    any of them
}