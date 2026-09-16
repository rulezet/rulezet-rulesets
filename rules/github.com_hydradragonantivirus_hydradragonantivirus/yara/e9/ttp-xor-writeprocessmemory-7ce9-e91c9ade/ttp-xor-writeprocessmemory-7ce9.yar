rule TTP_XOR_WriteProcessMemory_7ce9 {
  strings:
    $key_7ce9 = { 2b 9b [2] 19 b9 [2] 1f 8c [2] 31 8c [2] 0e 90 }

  condition:
    any of them
}