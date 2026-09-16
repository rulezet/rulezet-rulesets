rule TTP_XOR_WriteProcessMemory_d644 {
  strings:
    $key_d644 = { 81 36 [2] b3 14 [2] b5 21 [2] 9b 21 [2] a4 3d }

  condition:
    any of them
}