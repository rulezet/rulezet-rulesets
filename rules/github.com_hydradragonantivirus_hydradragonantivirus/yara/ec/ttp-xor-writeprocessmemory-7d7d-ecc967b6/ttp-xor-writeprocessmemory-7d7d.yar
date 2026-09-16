rule TTP_XOR_WriteProcessMemory_7d7d {
  strings:
    $key_7d7d = { 2a 0f [2] 18 2d [2] 1e 18 [2] 30 18 [2] 0f 04 }

  condition:
    any of them
}