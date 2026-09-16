rule TTP_XOR_WriteProcessMemory_3d11 {
  strings:
    $key_3d11 = { 6a 63 [2] 58 41 [2] 5e 74 [2] 70 74 [2] 4f 68 }

  condition:
    any of them
}