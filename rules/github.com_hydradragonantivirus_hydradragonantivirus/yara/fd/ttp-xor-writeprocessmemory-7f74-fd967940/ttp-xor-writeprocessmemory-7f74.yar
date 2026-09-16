rule TTP_XOR_WriteProcessMemory_7f74 {
  strings:
    $key_7f74 = { 28 06 [2] 1a 24 [2] 1c 11 [2] 32 11 [2] 0d 0d }

  condition:
    any of them
}