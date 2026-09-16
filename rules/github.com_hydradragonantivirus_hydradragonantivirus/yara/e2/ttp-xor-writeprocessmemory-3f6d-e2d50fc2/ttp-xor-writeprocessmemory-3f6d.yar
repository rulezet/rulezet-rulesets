rule TTP_XOR_WriteProcessMemory_3f6d {
  strings:
    $key_3f6d = { 68 1f [2] 5a 3d [2] 5c 08 [2] 72 08 [2] 4d 14 }

  condition:
    any of them
}