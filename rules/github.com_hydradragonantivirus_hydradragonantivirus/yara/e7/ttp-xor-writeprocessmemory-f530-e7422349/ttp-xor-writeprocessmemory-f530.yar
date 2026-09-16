rule TTP_XOR_WriteProcessMemory_f530 {
  strings:
    $key_f530 = { a2 42 [2] 90 60 [2] 96 55 [2] b8 55 [2] 87 49 }

  condition:
    any of them
}