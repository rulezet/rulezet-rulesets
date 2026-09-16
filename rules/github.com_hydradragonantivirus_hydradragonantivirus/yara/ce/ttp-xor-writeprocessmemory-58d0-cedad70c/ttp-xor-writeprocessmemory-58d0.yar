rule TTP_XOR_WriteProcessMemory_58d0 {
  strings:
    $key_58d0 = { 0f a2 [2] 3d 80 [2] 3b b5 [2] 15 b5 [2] 2a a9 }

  condition:
    any of them
}