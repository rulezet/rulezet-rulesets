rule TTP_XOR_WriteProcessMemory_2e69 {
  strings:
    $key_2e69 = { 79 1b [2] 4b 39 [2] 4d 0c [2] 63 0c [2] 5c 10 }

  condition:
    any of them
}