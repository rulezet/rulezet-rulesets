rule TTP_XOR_WriteProcessMemory_5813 {
  strings:
    $key_5813 = { 0f 61 [2] 3d 43 [2] 3b 76 [2] 15 76 [2] 2a 6a }

  condition:
    any of them
}