rule TTP_XOR_WriteProcessMemory_6035 {
  strings:
    $key_6035 = { 37 47 [2] 05 65 [2] 03 50 [2] 2d 50 [2] 12 4c }

  condition:
    any of them
}