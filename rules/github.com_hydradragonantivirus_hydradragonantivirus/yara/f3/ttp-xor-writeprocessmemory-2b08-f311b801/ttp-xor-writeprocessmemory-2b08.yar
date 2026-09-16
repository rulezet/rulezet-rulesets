rule TTP_XOR_WriteProcessMemory_2b08 {
  strings:
    $key_2b08 = { 7c 7a [2] 4e 58 [2] 48 6d [2] 66 6d [2] 59 71 }

  condition:
    any of them
}