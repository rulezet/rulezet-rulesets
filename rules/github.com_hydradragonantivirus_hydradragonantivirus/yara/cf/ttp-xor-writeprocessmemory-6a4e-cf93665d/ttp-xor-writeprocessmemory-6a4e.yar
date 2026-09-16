rule TTP_XOR_WriteProcessMemory_6a4e {
  strings:
    $key_6a4e = { 3d 3c [2] 0f 1e [2] 09 2b [2] 27 2b [2] 18 37 }

  condition:
    any of them
}