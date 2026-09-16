rule TTP_XOR_WriteProcessMemory_1338 {
  strings:
    $key_1338 = { 44 4a [2] 76 68 [2] 70 5d [2] 5e 5d [2] 61 41 }

  condition:
    any of them
}