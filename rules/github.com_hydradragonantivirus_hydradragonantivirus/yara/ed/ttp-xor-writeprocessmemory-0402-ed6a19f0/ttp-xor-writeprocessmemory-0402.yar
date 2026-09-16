rule TTP_XOR_WriteProcessMemory_0402 {
  strings:
    $key_0402 = { 53 70 [2] 61 52 [2] 67 67 [2] 49 67 [2] 76 7b }

  condition:
    any of them
}