rule TTP_XOR_WriteProcessMemory_5830 {
  strings:
    $key_5830 = { 0f 42 [2] 3d 60 [2] 3b 55 [2] 15 55 [2] 2a 49 }

  condition:
    any of them
}