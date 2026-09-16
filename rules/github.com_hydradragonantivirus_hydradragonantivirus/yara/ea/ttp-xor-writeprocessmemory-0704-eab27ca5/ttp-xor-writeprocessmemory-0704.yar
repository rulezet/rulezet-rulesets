rule TTP_XOR_WriteProcessMemory_0704 {
  strings:
    $key_0704 = { 50 76 [2] 62 54 [2] 64 61 [2] 4a 61 [2] 75 7d }

  condition:
    any of them
}