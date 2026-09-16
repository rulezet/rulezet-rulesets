rule TTP_XOR_WriteProcessMemory_4c6d {
  strings:
    $key_4c6d = { 1b 1f [2] 29 3d [2] 2f 08 [2] 01 08 [2] 3e 14 }

  condition:
    any of them
}