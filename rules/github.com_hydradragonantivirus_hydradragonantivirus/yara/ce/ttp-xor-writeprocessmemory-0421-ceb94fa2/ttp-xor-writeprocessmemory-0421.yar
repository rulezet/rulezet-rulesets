rule TTP_XOR_WriteProcessMemory_0421 {
  strings:
    $key_0421 = { 53 53 [2] 61 71 [2] 67 44 [2] 49 44 [2] 76 58 }

  condition:
    any of them
}