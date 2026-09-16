rule TTP_XOR_WriteProcessMemory_7540 {
  strings:
    $key_7540 = { 22 32 [2] 10 10 [2] 16 25 [2] 38 25 [2] 07 39 }

  condition:
    any of them
}