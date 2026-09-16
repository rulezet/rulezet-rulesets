rule TTP_XOR_WriteProcessMemory_ddd3 {
  strings:
    $key_ddd3 = { 8a a1 [2] b8 83 [2] be b6 [2] 90 b6 [2] af aa }

  condition:
    any of them
}