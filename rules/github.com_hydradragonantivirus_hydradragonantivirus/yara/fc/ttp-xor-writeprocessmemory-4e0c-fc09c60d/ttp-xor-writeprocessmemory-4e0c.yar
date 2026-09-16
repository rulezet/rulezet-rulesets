rule TTP_XOR_WriteProcessMemory_4e0c {
  strings:
    $key_4e0c = { 19 7e [2] 2b 5c [2] 2d 69 [2] 03 69 [2] 3c 75 }

  condition:
    any of them
}