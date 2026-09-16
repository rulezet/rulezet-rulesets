rule TTP_XOR_WriteProcessMemory_151b {
  strings:
    $key_151b = { 42 69 [2] 70 4b [2] 76 7e [2] 58 7e [2] 67 62 }

  condition:
    any of them
}