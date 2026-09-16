rule TTP_XOR_WriteProcessMemory_6a5b {
  strings:
    $key_6a5b = { 3d 29 [2] 0f 0b [2] 09 3e [2] 27 3e [2] 18 22 }

  condition:
    any of them
}