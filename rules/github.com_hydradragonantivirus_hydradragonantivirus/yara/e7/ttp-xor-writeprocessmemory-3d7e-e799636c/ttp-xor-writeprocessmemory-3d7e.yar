rule TTP_XOR_WriteProcessMemory_3d7e {
  strings:
    $key_3d7e = { 6a 0c [2] 58 2e [2] 5e 1b [2] 70 1b [2] 4f 07 }

  condition:
    any of them
}