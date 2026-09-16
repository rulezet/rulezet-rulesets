rule TTP_XOR_WriteProcessMemory_70f1 {
  strings:
    $key_70f1 = { 27 83 [2] 15 a1 [2] 13 94 [2] 3d 94 [2] 02 88 }

  condition:
    any of them
}