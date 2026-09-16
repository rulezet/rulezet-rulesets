rule TTP_XOR_WriteProcessMemory_f357 {
  strings:
    $key_f357 = { a4 25 [2] 96 07 [2] 90 32 [2] be 32 [2] 81 2e }

  condition:
    any of them
}