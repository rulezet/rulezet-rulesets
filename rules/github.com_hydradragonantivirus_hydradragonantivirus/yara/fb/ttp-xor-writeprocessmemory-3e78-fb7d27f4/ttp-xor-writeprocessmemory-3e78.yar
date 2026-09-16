rule TTP_XOR_WriteProcessMemory_3e78 {
  strings:
    $key_3e78 = { 69 0a [2] 5b 28 [2] 5d 1d [2] 73 1d [2] 4c 01 }

  condition:
    any of them
}