rule TTP_XOR_WriteProcessMemory_584d {
  strings:
    $key_584d = { 0f 3f [2] 3d 1d [2] 3b 28 [2] 15 28 [2] 2a 34 }

  condition:
    any of them
}