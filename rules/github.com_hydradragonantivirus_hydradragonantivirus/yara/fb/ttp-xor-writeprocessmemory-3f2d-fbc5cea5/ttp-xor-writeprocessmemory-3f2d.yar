rule TTP_XOR_WriteProcessMemory_3f2d {
  strings:
    $key_3f2d = { 68 5f [2] 5a 7d [2] 5c 48 [2] 72 48 [2] 4d 54 }

  condition:
    any of them
}