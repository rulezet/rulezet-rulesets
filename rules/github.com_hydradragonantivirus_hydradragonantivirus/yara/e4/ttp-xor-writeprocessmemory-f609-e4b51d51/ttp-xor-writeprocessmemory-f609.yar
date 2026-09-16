rule TTP_XOR_WriteProcessMemory_f609 {
  strings:
    $key_f609 = { a1 7b [2] 93 59 [2] 95 6c [2] bb 6c [2] 84 70 }

  condition:
    any of them
}