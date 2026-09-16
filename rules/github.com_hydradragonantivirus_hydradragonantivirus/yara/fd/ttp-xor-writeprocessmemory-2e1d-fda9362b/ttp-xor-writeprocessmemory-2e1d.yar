rule TTP_XOR_WriteProcessMemory_2e1d {
  strings:
    $key_2e1d = { 79 6f [2] 4b 4d [2] 4d 78 [2] 63 78 [2] 5c 64 }

  condition:
    any of them
}