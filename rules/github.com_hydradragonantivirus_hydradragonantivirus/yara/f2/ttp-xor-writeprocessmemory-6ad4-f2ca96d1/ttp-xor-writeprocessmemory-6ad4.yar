rule TTP_XOR_WriteProcessMemory_6ad4 {
  strings:
    $key_6ad4 = { 3d a6 [2] 0f 84 [2] 09 b1 [2] 27 b1 [2] 18 ad }

  condition:
    any of them
}