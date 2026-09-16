rule TTP_XOR_WriteProcessMemory_5877 {
  strings:
    $key_5877 = { 0f 05 [2] 3d 27 [2] 3b 12 [2] 15 12 [2] 2a 0e }

  condition:
    any of them
}