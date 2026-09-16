rule TTP_XOR_WriteProcessMemory_6a60 {
  strings:
    $key_6a60 = { 3d 12 [2] 0f 30 [2] 09 05 [2] 27 05 [2] 18 19 }

  condition:
    any of them
}