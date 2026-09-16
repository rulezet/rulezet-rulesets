rule TTP_XOR_WriteProcessMemory_6d7d {
  strings:
    $key_6d7d = { 3a 0f [2] 08 2d [2] 0e 18 [2] 20 18 [2] 1f 04 }

  condition:
    any of them
}