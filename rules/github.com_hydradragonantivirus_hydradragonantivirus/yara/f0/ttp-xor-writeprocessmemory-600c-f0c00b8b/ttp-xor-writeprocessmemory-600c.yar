rule TTP_XOR_WriteProcessMemory_600c {
  strings:
    $key_600c = { 37 7e [2] 05 5c [2] 03 69 [2] 2d 69 [2] 12 75 }

  condition:
    any of them
}