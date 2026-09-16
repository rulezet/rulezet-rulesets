rule TTP_XOR_WriteProcessMemory_3d4c {
  strings:
    $key_3d4c = { 6a 3e [2] 58 1c [2] 5e 29 [2] 70 29 [2] 4f 35 }

  condition:
    any of them
}