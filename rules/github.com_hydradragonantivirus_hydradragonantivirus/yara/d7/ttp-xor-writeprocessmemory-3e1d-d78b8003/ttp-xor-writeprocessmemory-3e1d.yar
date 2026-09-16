rule TTP_XOR_WriteProcessMemory_3e1d {
  strings:
    $key_3e1d = { 69 6f [2] 5b 4d [2] 5d 78 [2] 73 78 [2] 4c 64 }

  condition:
    any of them
}