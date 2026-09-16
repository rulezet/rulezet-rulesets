rule TTP_XOR_WriteProcessMemory_5238 {
  strings:
    $key_5238 = { 05 4a [2] 37 68 [2] 31 5d [2] 1f 5d [2] 20 41 }

  condition:
    any of them
}