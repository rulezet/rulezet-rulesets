rule TTP_XOR_WriteProcessMemory_3e68 {
  strings:
    $key_3e68 = { 69 1a [2] 5b 38 [2] 5d 0d [2] 73 0d [2] 4c 11 }

  condition:
    any of them
}