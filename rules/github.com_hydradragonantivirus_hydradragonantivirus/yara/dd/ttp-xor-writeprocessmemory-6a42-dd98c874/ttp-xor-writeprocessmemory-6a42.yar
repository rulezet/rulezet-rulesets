rule TTP_XOR_WriteProcessMemory_6a42 {
  strings:
    $key_6a42 = { 3d 30 [2] 0f 12 [2] 09 27 [2] 27 27 [2] 18 3b }

  condition:
    any of them
}