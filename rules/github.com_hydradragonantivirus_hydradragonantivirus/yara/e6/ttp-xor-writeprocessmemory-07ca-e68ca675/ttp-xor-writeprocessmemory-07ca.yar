rule TTP_XOR_WriteProcessMemory_07ca {
  strings:
    $key_07ca = { 50 b8 [2] 62 9a [2] 64 af [2] 4a af [2] 75 b3 }

  condition:
    any of them
}