rule TTP_XOR_WriteProcessMemory_0d08 {
  strings:
    $key_0d08 = { 5a 7a [2] 68 58 [2] 6e 6d [2] 40 6d [2] 7f 71 }

  condition:
    any of them
}