rule TTP_XOR_WriteProcessMemory_6a51 {
  strings:
    $key_6a51 = { 3d 23 [2] 0f 01 [2] 09 34 [2] 27 34 [2] 18 28 }

  condition:
    any of them
}