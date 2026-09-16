rule TTP_XOR_WriteProcessMemory_4a48 {
  strings:
    $key_4a48 = { 1d 3a [2] 2f 18 [2] 29 2d [2] 07 2d [2] 38 31 }

  condition:
    any of them
}