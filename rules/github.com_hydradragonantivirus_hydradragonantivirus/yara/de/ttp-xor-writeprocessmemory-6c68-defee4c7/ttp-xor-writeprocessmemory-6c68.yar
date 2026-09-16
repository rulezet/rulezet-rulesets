rule TTP_XOR_WriteProcessMemory_6c68 {
  strings:
    $key_6c68 = { 3b 1a [2] 09 38 [2] 0f 0d [2] 21 0d [2] 1e 11 }

  condition:
    any of them
}