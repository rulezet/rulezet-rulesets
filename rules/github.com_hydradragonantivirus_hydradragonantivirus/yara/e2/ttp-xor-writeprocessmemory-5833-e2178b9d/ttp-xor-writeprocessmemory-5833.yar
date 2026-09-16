rule TTP_XOR_WriteProcessMemory_5833 {
  strings:
    $key_5833 = { 0f 41 [2] 3d 63 [2] 3b 56 [2] 15 56 [2] 2a 4a }

  condition:
    any of them
}