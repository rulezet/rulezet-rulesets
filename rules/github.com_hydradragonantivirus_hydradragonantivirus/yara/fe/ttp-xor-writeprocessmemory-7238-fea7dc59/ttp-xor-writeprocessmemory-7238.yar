rule TTP_XOR_WriteProcessMemory_7238 {
  strings:
    $key_7238 = { 25 4a [2] 17 68 [2] 11 5d [2] 3f 5d [2] 00 41 }

  condition:
    any of them
}