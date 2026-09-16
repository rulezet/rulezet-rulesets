rule TTP_XOR_WriteProcessMemory_3c7d {
  strings:
    $key_3c7d = { 6b 0f [2] 59 2d [2] 5f 18 [2] 71 18 [2] 4e 04 }

  condition:
    any of them
}