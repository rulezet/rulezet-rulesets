rule TTP_XOR_WriteProcessMemory_0acd {
  strings:
    $key_0acd = { 5d bf [2] 6f 9d [2] 69 a8 [2] 47 a8 [2] 78 b4 }

  condition:
    any of them
}