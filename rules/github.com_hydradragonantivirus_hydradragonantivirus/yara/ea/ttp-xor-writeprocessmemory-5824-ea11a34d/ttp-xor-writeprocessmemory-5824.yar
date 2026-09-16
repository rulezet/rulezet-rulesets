rule TTP_XOR_WriteProcessMemory_5824 {
  strings:
    $key_5824 = { 0f 56 [2] 3d 74 [2] 3b 41 [2] 15 41 [2] 2a 5d }

  condition:
    any of them
}