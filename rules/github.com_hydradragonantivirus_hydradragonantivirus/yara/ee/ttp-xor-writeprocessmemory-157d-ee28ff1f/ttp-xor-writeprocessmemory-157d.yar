rule TTP_XOR_WriteProcessMemory_157d {
  strings:
    $key_157d = { 42 0f [2] 70 2d [2] 76 18 [2] 58 18 [2] 67 04 }

  condition:
    any of them
}