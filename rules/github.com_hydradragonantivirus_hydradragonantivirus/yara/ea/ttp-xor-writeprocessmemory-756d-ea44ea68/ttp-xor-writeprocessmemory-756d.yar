rule TTP_XOR_WriteProcessMemory_756d {
  strings:
    $key_756d = { 22 1f [2] 10 3d [2] 16 08 [2] 38 08 [2] 07 14 }

  condition:
    any of them
}