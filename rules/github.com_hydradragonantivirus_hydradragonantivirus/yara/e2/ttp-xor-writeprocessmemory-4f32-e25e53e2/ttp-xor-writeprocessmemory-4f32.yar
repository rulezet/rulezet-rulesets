rule TTP_XOR_WriteProcessMemory_4f32 {
  strings:
    $key_4f32 = { 18 40 [2] 2a 62 [2] 2c 57 [2] 02 57 [2] 3d 4b }

  condition:
    any of them
}