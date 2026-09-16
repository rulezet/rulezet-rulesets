rule TTP_XOR_WriteProcessMemory_f560 {
  strings:
    $key_f560 = { a2 12 [2] 90 30 [2] 96 05 [2] b8 05 [2] 87 19 }

  condition:
    any of them
}