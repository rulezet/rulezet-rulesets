rule TTP_XOR_WriteProcessMemory_2e78 {
  strings:
    $key_2e78 = { 79 0a [2] 4b 28 [2] 4d 1d [2] 63 1d [2] 5c 01 }

  condition:
    any of them
}