rule TTP_XOR_WriteProcessMemory_705b {
  strings:
    $key_705b = { 27 29 [2] 15 0b [2] 13 3e [2] 3d 3e [2] 02 22 }

  condition:
    any of them
}