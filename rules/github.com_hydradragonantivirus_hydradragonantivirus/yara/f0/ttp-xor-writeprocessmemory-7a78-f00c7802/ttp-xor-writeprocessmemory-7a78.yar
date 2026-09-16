rule TTP_XOR_WriteProcessMemory_7a78 {
  strings:
    $key_7a78 = { 2d 0a [2] 1f 28 [2] 19 1d [2] 37 1d [2] 08 01 }

  condition:
    any of them
}