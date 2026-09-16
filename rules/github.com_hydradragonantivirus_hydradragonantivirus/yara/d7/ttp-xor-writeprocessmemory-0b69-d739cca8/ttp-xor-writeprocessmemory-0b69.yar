rule TTP_XOR_WriteProcessMemory_0b69 {
  strings:
    $key_0b69 = { 5c 1b [2] 6e 39 [2] 68 0c [2] 46 0c [2] 79 10 }

  condition:
    any of them
}