rule TTP_XOR_WriteProcessMemory_6a6c {
  strings:
    $key_6a6c = { 3d 1e [2] 0f 3c [2] 09 09 [2] 27 09 [2] 18 15 }

  condition:
    any of them
}