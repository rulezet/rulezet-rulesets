rule TTP_XOR_WriteProcessMemory_7d6d {
  strings:
    $key_7d6d = { 2a 1f [2] 18 3d [2] 1e 08 [2] 30 08 [2] 0f 14 }

  condition:
    any of them
}