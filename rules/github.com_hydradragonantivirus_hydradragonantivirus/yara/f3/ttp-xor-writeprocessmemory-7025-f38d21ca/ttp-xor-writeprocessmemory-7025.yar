rule TTP_XOR_WriteProcessMemory_7025 {
  strings:
    $key_7025 = { 27 57 [2] 15 75 [2] 13 40 [2] 3d 40 [2] 02 5c }

  condition:
    any of them
}