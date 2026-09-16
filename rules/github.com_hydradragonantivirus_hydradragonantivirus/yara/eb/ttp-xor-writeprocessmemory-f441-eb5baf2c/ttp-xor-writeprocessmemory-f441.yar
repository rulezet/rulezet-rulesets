rule TTP_XOR_WriteProcessMemory_f441 {
  strings:
    $key_f441 = { a3 33 [2] 91 11 [2] 97 24 [2] b9 24 [2] 86 38 }

  condition:
    any of them
}