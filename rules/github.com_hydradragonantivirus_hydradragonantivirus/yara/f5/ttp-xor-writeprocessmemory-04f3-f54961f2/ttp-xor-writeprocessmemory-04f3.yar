rule TTP_XOR_WriteProcessMemory_04f3 {
  strings:
    $key_04f3 = { 53 81 [2] 61 a3 [2] 67 96 [2] 49 96 [2] 76 8a }

  condition:
    any of them
}