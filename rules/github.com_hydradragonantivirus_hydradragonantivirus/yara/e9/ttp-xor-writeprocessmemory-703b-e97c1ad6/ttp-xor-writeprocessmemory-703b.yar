rule TTP_XOR_WriteProcessMemory_703b {
  strings:
    $key_703b = { 27 49 [2] 15 6b [2] 13 5e [2] 3d 5e [2] 02 42 }

  condition:
    any of them
}