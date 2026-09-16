rule TTP_XOR_WriteProcessMemory_f686 {
  strings:
    $key_f686 = { a1 f4 [2] 93 d6 [2] 95 e3 [2] bb e3 [2] 84 ff }

  condition:
    any of them
}