rule TTP_XOR_WriteProcessMemory_0602 {
  strings:
    $key_0602 = { 51 70 [2] 63 52 [2] 65 67 [2] 4b 67 [2] 74 7b }

  condition:
    any of them
}