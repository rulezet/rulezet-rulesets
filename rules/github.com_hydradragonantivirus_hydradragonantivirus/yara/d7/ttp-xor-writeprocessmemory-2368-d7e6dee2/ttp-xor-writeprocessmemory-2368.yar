rule TTP_XOR_WriteProcessMemory_2368 {
  strings:
    $key_2368 = { 74 1a [2] 46 38 [2] 40 0d [2] 6e 0d [2] 51 11 }

  condition:
    any of them
}