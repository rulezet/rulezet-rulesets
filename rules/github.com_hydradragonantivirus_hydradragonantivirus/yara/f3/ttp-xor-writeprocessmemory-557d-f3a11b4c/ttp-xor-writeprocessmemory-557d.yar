rule TTP_XOR_WriteProcessMemory_557d {
  strings:
    $key_557d = { 02 0f [2] 30 2d [2] 36 18 [2] 18 18 [2] 27 04 }

  condition:
    any of them
}