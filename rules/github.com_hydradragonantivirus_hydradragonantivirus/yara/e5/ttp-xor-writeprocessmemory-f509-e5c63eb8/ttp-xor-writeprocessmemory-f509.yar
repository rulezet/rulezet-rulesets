rule TTP_XOR_WriteProcessMemory_f509 {
  strings:
    $key_f509 = { a2 7b [2] 90 59 [2] 96 6c [2] b8 6c [2] 87 70 }

  condition:
    any of them
}