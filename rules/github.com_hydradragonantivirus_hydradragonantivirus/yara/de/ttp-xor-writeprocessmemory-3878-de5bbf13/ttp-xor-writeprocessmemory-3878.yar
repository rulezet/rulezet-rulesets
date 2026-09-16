rule TTP_XOR_WriteProcessMemory_3878 {
  strings:
    $key_3878 = { 6f 0a [2] 5d 28 [2] 5b 1d [2] 75 1d [2] 4a 01 }

  condition:
    any of them
}