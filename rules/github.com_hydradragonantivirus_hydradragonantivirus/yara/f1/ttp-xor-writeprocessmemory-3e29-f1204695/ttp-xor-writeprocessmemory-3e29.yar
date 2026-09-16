rule TTP_XOR_WriteProcessMemory_3e29 {
  strings:
    $key_3e29 = { 69 5b [2] 5b 79 [2] 5d 4c [2] 73 4c [2] 4c 50 }

  condition:
    any of them
}