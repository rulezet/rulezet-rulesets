rule TTP_XOR_WriteProcessMemory_2f6d {
  strings:
    $key_2f6d = { 78 1f [2] 4a 3d [2] 4c 08 [2] 62 08 [2] 5d 14 }

  condition:
    any of them
}