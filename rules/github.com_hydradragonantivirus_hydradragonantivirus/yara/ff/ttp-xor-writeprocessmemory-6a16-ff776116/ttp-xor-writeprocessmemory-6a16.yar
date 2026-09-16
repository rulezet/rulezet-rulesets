rule TTP_XOR_WriteProcessMemory_6a16 {
  strings:
    $key_6a16 = { 3d 64 [2] 0f 46 [2] 09 73 [2] 27 73 [2] 18 6f }

  condition:
    any of them
}