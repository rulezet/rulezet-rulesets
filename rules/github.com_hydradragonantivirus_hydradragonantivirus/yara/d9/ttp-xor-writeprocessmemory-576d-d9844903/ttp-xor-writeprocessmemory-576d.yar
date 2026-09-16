rule TTP_XOR_WriteProcessMemory_576d {
  strings:
    $key_576d = { 00 1f [2] 32 3d [2] 34 08 [2] 1a 08 [2] 25 14 }

  condition:
    any of them
}