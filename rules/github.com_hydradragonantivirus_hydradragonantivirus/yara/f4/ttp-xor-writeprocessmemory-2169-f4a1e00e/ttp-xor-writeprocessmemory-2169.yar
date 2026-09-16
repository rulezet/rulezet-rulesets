rule TTP_XOR_WriteProcessMemory_2169 {
  strings:
    $key_2169 = { 76 1b [2] 44 39 [2] 42 0c [2] 6c 0c [2] 53 10 }

  condition:
    any of them
}