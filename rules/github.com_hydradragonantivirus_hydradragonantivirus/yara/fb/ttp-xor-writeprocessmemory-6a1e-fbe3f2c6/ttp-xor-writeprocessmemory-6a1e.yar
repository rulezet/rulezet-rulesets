rule TTP_XOR_WriteProcessMemory_6a1e {
  strings:
    $key_6a1e = { 3d 6c [2] 0f 4e [2] 09 7b [2] 27 7b [2] 18 67 }

  condition:
    any of them
}