rule TTP_XOR_WriteProcessMemory_6a65 {
  strings:
    $key_6a65 = { 3d 17 [2] 0f 35 [2] 09 00 [2] 27 00 [2] 18 1c }

  condition:
    any of them
}