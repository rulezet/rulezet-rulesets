rule TTP_XOR_WriteProcessMemory_04e2 {
  strings:
    $key_04e2 = { 53 90 [2] 61 b2 [2] 67 87 [2] 49 87 [2] 76 9b }

  condition:
    any of them
}