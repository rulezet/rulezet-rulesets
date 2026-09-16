rule TTP_XOR_WriteProcessMemory_3d10 {
  strings:
    $key_3d10 = { 6a 62 [2] 58 40 [2] 5e 75 [2] 70 75 [2] 4f 69 }

  condition:
    any of them
}