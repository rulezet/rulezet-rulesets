rule TTP_XOR_WriteProcessMemory_531d {
  strings:
    $key_531d = { 04 6f [2] 36 4d [2] 30 78 [2] 1e 78 [2] 21 64 }

  condition:
    any of them
}