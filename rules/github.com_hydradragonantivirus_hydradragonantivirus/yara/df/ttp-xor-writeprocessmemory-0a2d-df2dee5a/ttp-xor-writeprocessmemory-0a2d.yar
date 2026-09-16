rule TTP_XOR_WriteProcessMemory_0a2d {
  strings:
    $key_0a2d = { 5d 5f [2] 6f 7d [2] 69 48 [2] 47 48 [2] 78 54 }

  condition:
    any of them
}