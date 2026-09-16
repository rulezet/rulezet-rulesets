rule TTP_XOR_WriteProcessMemory_f603 {
  strings:
    $key_f603 = { a1 71 [2] 93 53 [2] 95 66 [2] bb 66 [2] 84 7a }

  condition:
    any of them
}