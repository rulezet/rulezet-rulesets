rule TTP_XOR_WriteProcessMemory_1978 {
  strings:
    $key_1978 = { 4e 0a [2] 7c 28 [2] 7a 1d [2] 54 1d [2] 6b 01 }

  condition:
    any of them
}