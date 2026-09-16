rule TTP_XOR_WriteProcessMemory_3513 {
  strings:
    $key_3513 = { 62 61 [2] 50 43 [2] 56 76 [2] 78 76 [2] 47 6a }

  condition:
    any of them
}