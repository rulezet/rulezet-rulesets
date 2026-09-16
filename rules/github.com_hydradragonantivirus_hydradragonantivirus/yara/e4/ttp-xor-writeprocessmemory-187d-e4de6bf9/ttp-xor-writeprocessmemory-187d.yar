rule TTP_XOR_WriteProcessMemory_187d {
  strings:
    $key_187d = { 4f 0f [2] 7d 2d [2] 7b 18 [2] 55 18 [2] 6a 04 }

  condition:
    any of them
}