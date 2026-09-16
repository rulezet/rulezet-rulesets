rule TTP_XOR_WriteProcessMemory_1acd {
  strings:
    $key_1acd = { 4d bf [2] 7f 9d [2] 79 a8 [2] 57 a8 [2] 68 b4 }

  condition:
    any of them
}