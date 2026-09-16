rule TTP_XOR_WriteProcessMemory_f60c {
  strings:
    $key_f60c = { a1 7e [2] 93 5c [2] 95 69 [2] bb 69 [2] 84 75 }

  condition:
    any of them
}