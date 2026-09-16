rule TTP_XOR_WriteProcessMemory_6a7b {
  strings:
    $key_6a7b = { 3d 09 [2] 0f 2b [2] 09 1e [2] 27 1e [2] 18 02 }

  condition:
    any of them
}