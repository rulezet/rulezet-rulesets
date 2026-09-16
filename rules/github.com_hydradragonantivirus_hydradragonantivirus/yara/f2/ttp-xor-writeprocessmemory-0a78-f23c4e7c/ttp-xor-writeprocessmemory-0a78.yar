rule TTP_XOR_WriteProcessMemory_0a78 {
  strings:
    $key_0a78 = { 5d 0a [2] 6f 28 [2] 69 1d [2] 47 1d [2] 78 01 }

  condition:
    any of them
}