rule TTP_XOR_WriteProcessMemory_4e0d {
  strings:
    $key_4e0d = { 19 7f [2] 2b 5d [2] 2d 68 [2] 03 68 [2] 3c 74 }

  condition:
    any of them
}