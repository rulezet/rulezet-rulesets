rule TTP_XOR_WriteProcessMemory_0440 {
  strings:
    $key_0440 = { 53 32 [2] 61 10 [2] 67 25 [2] 49 25 [2] 76 39 }

  condition:
    any of them
}