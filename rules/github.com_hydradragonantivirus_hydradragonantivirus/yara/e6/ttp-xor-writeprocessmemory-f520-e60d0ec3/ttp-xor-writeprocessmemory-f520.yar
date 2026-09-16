rule TTP_XOR_WriteProcessMemory_f520 {
  strings:
    $key_f520 = { a2 52 [2] 90 70 [2] 96 45 [2] b8 45 [2] 87 59 }

  condition:
    any of them
}