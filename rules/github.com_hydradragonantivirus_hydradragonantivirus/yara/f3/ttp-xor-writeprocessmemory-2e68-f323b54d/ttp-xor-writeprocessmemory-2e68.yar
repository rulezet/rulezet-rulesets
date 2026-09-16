rule TTP_XOR_WriteProcessMemory_2e68 {
  strings:
    $key_2e68 = { 79 1a [2] 4b 38 [2] 4d 0d [2] 63 0d [2] 5c 11 }

  condition:
    any of them
}