rule TTP_XOR_WriteProcessMemory_7acd {
  strings:
    $key_7acd = { 2d bf [2] 1f 9d [2] 19 a8 [2] 37 a8 [2] 08 b4 }

  condition:
    any of them
}