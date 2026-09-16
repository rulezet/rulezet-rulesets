rule TTP_XOR_WriteProcessMemory_5b68 {
  strings:
    $key_5b68 = { 0c 1a [2] 3e 38 [2] 38 0d [2] 16 0d [2] 29 11 }

  condition:
    any of them
}