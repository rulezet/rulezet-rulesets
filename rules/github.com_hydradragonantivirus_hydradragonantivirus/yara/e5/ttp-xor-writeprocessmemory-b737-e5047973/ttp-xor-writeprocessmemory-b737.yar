rule TTP_XOR_WriteProcessMemory_b737 {
  strings:
    $key_b737 = { e0 45 [2] d2 67 [2] d4 52 [2] fa 52 [2] c5 4e }

  condition:
    any of them
}