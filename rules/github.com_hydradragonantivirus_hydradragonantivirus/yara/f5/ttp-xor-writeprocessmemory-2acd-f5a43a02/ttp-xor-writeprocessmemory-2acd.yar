rule TTP_XOR_WriteProcessMemory_2acd {
  strings:
    $key_2acd = { 7d bf [2] 4f 9d [2] 49 a8 [2] 67 a8 [2] 58 b4 }

  condition:
    any of them
}