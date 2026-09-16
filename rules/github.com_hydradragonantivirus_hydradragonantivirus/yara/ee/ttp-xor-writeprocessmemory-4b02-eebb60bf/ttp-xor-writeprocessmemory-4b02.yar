rule TTP_XOR_WriteProcessMemory_4b02 {
  strings:
    $key_4b02 = { 1c 70 [2] 2e 52 [2] 28 67 [2] 06 67 [2] 39 7b }

  condition:
    any of them
}