rule TTP_XOR_WriteProcessMemory_7c78 {
  strings:
    $key_7c78 = { 2b 0a [2] 19 28 [2] 1f 1d [2] 31 1d [2] 0e 01 }

  condition:
    any of them
}