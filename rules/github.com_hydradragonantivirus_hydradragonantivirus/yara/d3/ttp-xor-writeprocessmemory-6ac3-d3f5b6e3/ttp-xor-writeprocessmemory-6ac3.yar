rule TTP_XOR_WriteProcessMemory_6ac3 {
  strings:
    $key_6ac3 = { 3d b1 [2] 0f 93 [2] 09 a6 [2] 27 a6 [2] 18 ba }

  condition:
    any of them
}