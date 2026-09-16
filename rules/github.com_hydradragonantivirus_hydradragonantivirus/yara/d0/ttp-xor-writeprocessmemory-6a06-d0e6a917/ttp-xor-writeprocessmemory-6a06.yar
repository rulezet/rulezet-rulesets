rule TTP_XOR_WriteProcessMemory_6a06 {
  strings:
    $key_6a06 = { 3d 74 [2] 0f 56 [2] 09 63 [2] 27 63 [2] 18 7f }

  condition:
    any of them
}