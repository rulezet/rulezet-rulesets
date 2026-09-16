rule TTP_XOR_WriteProcessMemory_376d {
  strings:
    $key_376d = { 60 1f [2] 52 3d [2] 54 08 [2] 7a 08 [2] 45 14 }

  condition:
    any of them
}