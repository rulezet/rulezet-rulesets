rule TTP_XOR_WriteProcessMemory_0a21 {
  strings:
    $key_0a21 = { 5d 53 [2] 6f 71 [2] 69 44 [2] 47 44 [2] 78 58 }

  condition:
    any of them
}