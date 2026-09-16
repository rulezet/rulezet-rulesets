rule TTP_XOR_WriteProcessMemory_0854 {
  strings:
    $key_0854 = { 5f 26 [2] 6d 04 [2] 6b 31 [2] 45 31 [2] 7a 2d }

  condition:
    any of them
}