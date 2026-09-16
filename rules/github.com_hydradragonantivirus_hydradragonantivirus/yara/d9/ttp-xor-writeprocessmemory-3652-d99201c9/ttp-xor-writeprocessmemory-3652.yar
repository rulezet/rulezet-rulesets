rule TTP_XOR_WriteProcessMemory_3652 {
  strings:
    $key_3652 = { 61 20 [2] 53 02 [2] 55 37 [2] 7b 37 [2] 44 2b }

  condition:
    any of them
}