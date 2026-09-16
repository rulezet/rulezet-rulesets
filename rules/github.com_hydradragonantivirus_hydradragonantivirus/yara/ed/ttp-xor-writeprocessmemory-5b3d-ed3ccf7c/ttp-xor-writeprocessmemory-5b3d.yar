rule TTP_XOR_WriteProcessMemory_5b3d {
  strings:
    $key_5b3d = { 0c 4f [2] 3e 6d [2] 38 58 [2] 16 58 [2] 29 44 }

  condition:
    any of them
}