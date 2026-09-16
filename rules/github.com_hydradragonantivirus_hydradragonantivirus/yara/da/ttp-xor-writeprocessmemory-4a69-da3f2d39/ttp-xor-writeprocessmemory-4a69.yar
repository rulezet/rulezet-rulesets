rule TTP_XOR_WriteProcessMemory_4a69 {
  strings:
    $key_4a69 = { 1d 1b [2] 2f 39 [2] 29 0c [2] 07 0c [2] 38 10 }

  condition:
    any of them
}