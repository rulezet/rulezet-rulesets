rule TTP_XOR_WriteProcessMemory_6844 {
  strings:
    $key_6844 = { 3f 36 [2] 0d 14 [2] 0b 21 [2] 25 21 [2] 1a 3d }

  condition:
    any of them
}