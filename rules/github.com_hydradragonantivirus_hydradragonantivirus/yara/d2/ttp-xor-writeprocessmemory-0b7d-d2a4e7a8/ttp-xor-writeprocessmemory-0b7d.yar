rule TTP_XOR_WriteProcessMemory_0b7d {
  strings:
    $key_0b7d = { 5c 0f [2] 6e 2d [2] 68 18 [2] 46 18 [2] 79 04 }

  condition:
    any of them
}