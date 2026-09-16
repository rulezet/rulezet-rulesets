rule TTP_XOR_WriteProcessMemory_c978 {
  strings:
    $key_c978 = { 9e 0a [2] ac 28 [2] aa 1d [2] 84 1d [2] bb 01 }

  condition:
    any of them
}