rule TTP_XOR_WriteProcessMemory_e744 {
  strings:
    $key_e744 = { b0 36 [2] 82 14 [2] 84 21 [2] aa 21 [2] 95 3d }

  condition:
    any of them
}