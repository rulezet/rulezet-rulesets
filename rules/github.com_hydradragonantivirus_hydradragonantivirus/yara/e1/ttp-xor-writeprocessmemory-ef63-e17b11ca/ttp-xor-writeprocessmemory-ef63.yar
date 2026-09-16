rule TTP_XOR_WriteProcessMemory_ef63 {
  strings:
    $key_ef63 = { b8 11 [2] 8a 33 [2] 8c 06 [2] a2 06 [2] 9d 1a }

  condition:
    any of them
}