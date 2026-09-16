rule TTP_XOR_WriteProcessMemory_4e69 {
  strings:
    $key_4e69 = { 19 1b [2] 2b 39 [2] 2d 0c [2] 03 0c [2] 3c 10 }

  condition:
    any of them
}