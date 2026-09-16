rule TTP_XOR_WriteProcessMemory_4ce9 {
  strings:
    $key_4ce9 = { 1b 9b [2] 29 b9 [2] 2f 8c [2] 01 8c [2] 3e 90 }

  condition:
    any of them
}