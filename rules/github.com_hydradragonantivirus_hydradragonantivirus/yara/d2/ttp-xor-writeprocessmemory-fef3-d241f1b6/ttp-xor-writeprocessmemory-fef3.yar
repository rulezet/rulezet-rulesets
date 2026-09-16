rule TTP_XOR_WriteProcessMemory_fef3 {
  strings:
    $key_fef3 = { a9 81 [2] 9b a3 [2] 9d 96 [2] b3 96 [2] 8c 8a }

  condition:
    any of them
}