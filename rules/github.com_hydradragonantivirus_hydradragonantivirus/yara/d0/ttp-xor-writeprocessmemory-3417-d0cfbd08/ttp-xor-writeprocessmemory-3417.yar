rule TTP_XOR_WriteProcessMemory_3417 {
  strings:
    $key_3417 = { 63 65 [2] 51 47 [2] 57 72 [2] 79 72 [2] 46 6e }

  condition:
    any of them
}