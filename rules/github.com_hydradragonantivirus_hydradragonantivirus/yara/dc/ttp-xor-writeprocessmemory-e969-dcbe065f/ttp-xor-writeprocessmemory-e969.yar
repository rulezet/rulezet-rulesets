rule TTP_XOR_WriteProcessMemory_e969 {
  strings:
    $key_e969 = { be 1b [2] 8c 39 [2] 8a 0c [2] a4 0c [2] 9b 10 }

  condition:
    any of them
}