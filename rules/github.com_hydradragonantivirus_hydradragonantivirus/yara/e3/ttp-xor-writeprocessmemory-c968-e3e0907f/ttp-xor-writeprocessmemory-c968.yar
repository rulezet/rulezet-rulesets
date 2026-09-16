rule TTP_XOR_WriteProcessMemory_c968 {
  strings:
    $key_c968 = { 9e 1a [2] ac 38 [2] aa 0d [2] 84 0d [2] bb 11 }

  condition:
    any of them
}