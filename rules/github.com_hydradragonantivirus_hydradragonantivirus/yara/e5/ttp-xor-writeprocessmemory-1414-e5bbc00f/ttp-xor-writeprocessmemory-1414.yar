rule TTP_XOR_WriteProcessMemory_1414 {
  strings:
    $key_1414 = { 43 66 [2] 71 44 [2] 77 71 [2] 59 71 [2] 66 6d }

  condition:
    any of them
}