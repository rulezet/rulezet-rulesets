rule TTP_XOR_WriteProcessMemory_5821 {
  strings:
    $key_5821 = { 0f 53 [2] 3d 71 [2] 3b 44 [2] 15 44 [2] 2a 58 }

  condition:
    any of them
}