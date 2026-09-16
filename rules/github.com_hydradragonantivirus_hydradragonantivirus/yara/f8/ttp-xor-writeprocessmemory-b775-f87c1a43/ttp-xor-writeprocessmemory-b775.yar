rule TTP_XOR_WriteProcessMemory_b775 {
  strings:
    $key_b775 = { e0 07 [2] d2 25 [2] d4 10 [2] fa 10 [2] c5 0c }

  condition:
    any of them
}