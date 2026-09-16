rule TTP_XOR_WriteProcessMemory_6a70 {
  strings:
    $key_6a70 = { 3d 02 [2] 0f 20 [2] 09 15 [2] 27 15 [2] 18 09 }

  condition:
    any of them
}