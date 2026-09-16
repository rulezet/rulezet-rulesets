rule TTP_XOR_WriteProcessMemory_f323 {
  strings:
    $key_f323 = { a4 51 [2] 96 73 [2] 90 46 [2] be 46 [2] 81 5a }

  condition:
    any of them
}