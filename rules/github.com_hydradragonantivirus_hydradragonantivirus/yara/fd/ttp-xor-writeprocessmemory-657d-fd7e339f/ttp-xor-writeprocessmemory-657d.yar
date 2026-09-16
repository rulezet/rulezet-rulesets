rule TTP_XOR_WriteProcessMemory_657d {
  strings:
    $key_657d = { 32 0f [2] 00 2d [2] 06 18 [2] 28 18 [2] 17 04 }

  condition:
    any of them
}