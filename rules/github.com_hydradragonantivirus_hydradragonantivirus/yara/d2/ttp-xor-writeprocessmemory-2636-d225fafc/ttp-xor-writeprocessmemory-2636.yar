rule TTP_XOR_WriteProcessMemory_2636 {
  strings:
    $key_2636 = { 71 44 [2] 43 66 [2] 45 53 [2] 6b 53 [2] 54 4f }

  condition:
    any of them
}