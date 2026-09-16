rule TTP_XOR_WriteProcessMemory_f531 {
  strings:
    $key_f531 = { a2 43 [2] 90 61 [2] 96 54 [2] b8 54 [2] 87 48 }

  condition:
    any of them
}