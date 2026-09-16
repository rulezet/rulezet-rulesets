rule TTP_XOR_WriteProcessMemory_4e1d {
  strings:
    $key_4e1d = { 19 6f [2] 2b 4d [2] 2d 78 [2] 03 78 [2] 3c 64 }

  condition:
    any of them
}