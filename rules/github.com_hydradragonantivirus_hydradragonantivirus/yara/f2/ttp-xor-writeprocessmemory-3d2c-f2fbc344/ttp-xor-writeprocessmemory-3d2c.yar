rule TTP_XOR_WriteProcessMemory_3d2c {
  strings:
    $key_3d2c = { 6a 5e [2] 58 7c [2] 5e 49 [2] 70 49 [2] 4f 55 }

  condition:
    any of them
}