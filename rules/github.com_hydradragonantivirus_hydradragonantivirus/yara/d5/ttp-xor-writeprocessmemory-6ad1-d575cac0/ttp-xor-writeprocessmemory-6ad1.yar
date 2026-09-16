rule TTP_XOR_WriteProcessMemory_6ad1 {
  strings:
    $key_6ad1 = { 3d a3 [2] 0f 81 [2] 09 b4 [2] 27 b4 [2] 18 a8 }

  condition:
    any of them
}