rule TTP_XOR_WriteProcessMemory_186d {
  strings:
    $key_186d = { 4f 1f [2] 7d 3d [2] 7b 08 [2] 55 08 [2] 6a 14 }

  condition:
    any of them
}