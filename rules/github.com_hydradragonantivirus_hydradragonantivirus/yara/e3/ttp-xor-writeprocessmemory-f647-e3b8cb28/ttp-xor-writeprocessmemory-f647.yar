rule TTP_XOR_WriteProcessMemory_f647 {
  strings:
    $key_f647 = { a1 35 [2] 93 17 [2] 95 22 [2] bb 22 [2] 84 3e }

  condition:
    any of them
}