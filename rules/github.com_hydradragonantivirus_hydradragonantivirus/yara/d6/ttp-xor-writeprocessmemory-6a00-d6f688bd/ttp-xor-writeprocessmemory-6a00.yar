rule TTP_XOR_WriteProcessMemory_6a00 {
  strings:
    $key_6a00 = { 3d 72 [2] 0f 50 [2] 09 65 [2] 27 65 [2] 18 79 }

  condition:
    any of them
}