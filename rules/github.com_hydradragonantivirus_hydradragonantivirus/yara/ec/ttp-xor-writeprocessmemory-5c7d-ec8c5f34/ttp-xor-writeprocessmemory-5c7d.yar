rule TTP_XOR_WriteProcessMemory_5c7d {
  strings:
    $key_5c7d = { 0b 0f [2] 39 2d [2] 3f 18 [2] 11 18 [2] 2e 04 }

  condition:
    any of them
}