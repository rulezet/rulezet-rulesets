rule TTP_XOR_WriteProcessMemory_637d {
  strings:
    $key_637d = { 34 0f [2] 06 2d [2] 00 18 [2] 2e 18 [2] 11 04 }

  condition:
    any of them
}