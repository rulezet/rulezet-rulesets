rule TTP_XOR_WriteProcessMemory_1169 {
  strings:
    $key_1169 = { 46 1b [2] 74 39 [2] 72 0c [2] 5c 0c [2] 63 10 }

  condition:
    any of them
}