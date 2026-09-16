rule TTP_XOR_WriteProcessMemory_5815 {
  strings:
    $key_5815 = { 0f 67 [2] 3d 45 [2] 3b 70 [2] 15 70 [2] 2a 6c }

  condition:
    any of them
}