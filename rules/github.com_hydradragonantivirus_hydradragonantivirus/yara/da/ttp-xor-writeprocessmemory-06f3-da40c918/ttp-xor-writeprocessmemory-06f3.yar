rule TTP_XOR_WriteProcessMemory_06f3 {
  strings:
    $key_06f3 = { 51 81 [2] 63 a3 [2] 65 96 [2] 4b 96 [2] 74 8a }

  condition:
    any of them
}