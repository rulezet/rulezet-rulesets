rule TTP_XOR_WriteProcessMemory_5820 {
  strings:
    $key_5820 = { 0f 52 [2] 3d 70 [2] 3b 45 [2] 15 45 [2] 2a 59 }

  condition:
    any of them
}