rule TTP_XOR_WriteProcessMemory_2d6d {
  strings:
    $key_2d6d = { 7a 1f [2] 48 3d [2] 4e 08 [2] 60 08 [2] 5f 14 }

  condition:
    any of them
}