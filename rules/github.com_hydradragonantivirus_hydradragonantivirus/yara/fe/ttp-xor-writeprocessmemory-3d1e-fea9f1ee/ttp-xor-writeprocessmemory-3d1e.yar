rule TTP_XOR_WriteProcessMemory_3d1e {
  strings:
    $key_3d1e = { 6a 6c [2] 58 4e [2] 5e 7b [2] 70 7b [2] 4f 67 }

  condition:
    any of them
}