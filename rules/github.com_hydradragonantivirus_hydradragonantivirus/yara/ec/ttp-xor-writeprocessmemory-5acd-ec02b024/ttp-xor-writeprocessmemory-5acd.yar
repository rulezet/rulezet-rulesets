rule TTP_XOR_WriteProcessMemory_5acd {
  strings:
    $key_5acd = { 0d bf [2] 3f 9d [2] 39 a8 [2] 17 a8 [2] 28 b4 }

  condition:
    any of them
}