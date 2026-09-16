rule TTP_XOR_WriteProcessMemory_0c68 {
  strings:
    $key_0c68 = { 5b 1a [2] 69 38 [2] 6f 0d [2] 41 0d [2] 7e 11 }

  condition:
    any of them
}