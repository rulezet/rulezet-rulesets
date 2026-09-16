rule TTP_XOR_WriteProcessMemory_5c48 {
  strings:
    $key_5c48 = { 0b 3a [2] 39 18 [2] 3f 2d [2] 11 2d [2] 2e 31 }

  condition:
    any of them
}