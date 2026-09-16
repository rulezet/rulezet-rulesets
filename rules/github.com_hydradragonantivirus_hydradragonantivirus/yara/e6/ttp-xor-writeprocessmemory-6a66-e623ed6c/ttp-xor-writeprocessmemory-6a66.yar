rule TTP_XOR_WriteProcessMemory_6a66 {
  strings:
    $key_6a66 = { 3d 14 [2] 0f 36 [2] 09 03 [2] 27 03 [2] 18 1f }

  condition:
    any of them
}