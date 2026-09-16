rule TTP_XOR_WriteProcessMemory_5857 {
  strings:
    $key_5857 = { 0f 25 [2] 3d 07 [2] 3b 32 [2] 15 32 [2] 2a 2e }

  condition:
    any of them
}