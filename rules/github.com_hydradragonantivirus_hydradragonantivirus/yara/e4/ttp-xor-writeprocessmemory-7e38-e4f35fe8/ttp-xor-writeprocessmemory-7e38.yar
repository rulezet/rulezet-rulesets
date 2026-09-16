rule TTP_XOR_WriteProcessMemory_7e38 {
  strings:
    $key_7e38 = { 29 4a [2] 1b 68 [2] 1d 5d [2] 33 5d [2] 0c 41 }

  condition:
    any of them
}