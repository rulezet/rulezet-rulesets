rule TTP_XOR_WriteProcessMemory_6af3 {
  strings:
    $key_6af3 = { 3d 81 [2] 0f a3 [2] 09 96 [2] 27 96 [2] 18 8a }

  condition:
    any of them
}