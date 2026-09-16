rule TTP_XOR_WriteProcessMemory_7e1d {
  strings:
    $key_7e1d = { 29 6f [2] 1b 4d [2] 1d 78 [2] 33 78 [2] 0c 64 }

  condition:
    any of them
}