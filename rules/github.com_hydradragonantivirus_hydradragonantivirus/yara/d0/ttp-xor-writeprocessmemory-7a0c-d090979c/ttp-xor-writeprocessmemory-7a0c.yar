rule TTP_XOR_WriteProcessMemory_7a0c {
  strings:
    $key_7a0c = { 2d 7e [2] 1f 5c [2] 19 69 [2] 37 69 [2] 08 75 }

  condition:
    any of them
}