rule TTP_XOR_WriteProcessMemory_2221 {
  strings:
    $key_2221 = { 75 53 [2] 47 71 [2] 41 44 [2] 6f 44 [2] 50 58 }

  condition:
    any of them
}