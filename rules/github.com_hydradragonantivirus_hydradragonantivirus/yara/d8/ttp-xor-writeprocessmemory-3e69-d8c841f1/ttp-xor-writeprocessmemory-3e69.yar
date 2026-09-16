rule TTP_XOR_WriteProcessMemory_3e69 {
  strings:
    $key_3e69 = { 69 1b [2] 5b 39 [2] 5d 0c [2] 73 0c [2] 4c 10 }

  condition:
    any of them
}