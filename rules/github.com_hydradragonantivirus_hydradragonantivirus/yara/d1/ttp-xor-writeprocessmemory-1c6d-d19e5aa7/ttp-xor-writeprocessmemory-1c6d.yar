rule TTP_XOR_WriteProcessMemory_1c6d {
  strings:
    $key_1c6d = { 4b 1f [2] 79 3d [2] 7f 08 [2] 51 08 [2] 6e 14 }

  condition:
    any of them
}