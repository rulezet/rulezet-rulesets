rule TTP_XOR_WriteProcessMemory_2654 {
  strings:
    $key_2654 = { 71 26 [2] 43 04 [2] 45 31 [2] 6b 31 [2] 54 2d }

  condition:
    any of them
}