rule TTP_XOR_WriteProcessMemory_2a78 {
  strings:
    $key_2a78 = { 7d 0a [2] 4f 28 [2] 49 1d [2] 67 1d [2] 58 01 }

  condition:
    any of them
}