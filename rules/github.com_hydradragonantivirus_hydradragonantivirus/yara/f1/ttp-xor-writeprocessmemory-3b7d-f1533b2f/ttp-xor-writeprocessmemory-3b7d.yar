rule TTP_XOR_WriteProcessMemory_3b7d {
  strings:
    $key_3b7d = { 6c 0f [2] 5e 2d [2] 58 18 [2] 76 18 [2] 49 04 }

  condition:
    any of them
}