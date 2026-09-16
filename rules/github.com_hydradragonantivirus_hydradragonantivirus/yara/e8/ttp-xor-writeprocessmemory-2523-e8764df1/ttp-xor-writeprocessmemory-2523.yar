rule TTP_XOR_WriteProcessMemory_2523 {
  strings:
    $key_2523 = { 72 51 [2] 40 73 [2] 46 46 [2] 68 46 [2] 57 5a }

  condition:
    any of them
}