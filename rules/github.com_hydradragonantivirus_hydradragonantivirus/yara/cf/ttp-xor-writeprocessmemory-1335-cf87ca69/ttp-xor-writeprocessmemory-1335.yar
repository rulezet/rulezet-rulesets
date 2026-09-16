rule TTP_XOR_WriteProcessMemory_1335 {
  strings:
    $key_1335 = { 44 47 [2] 76 65 [2] 70 50 [2] 5e 50 [2] 61 4c }

  condition:
    any of them
}