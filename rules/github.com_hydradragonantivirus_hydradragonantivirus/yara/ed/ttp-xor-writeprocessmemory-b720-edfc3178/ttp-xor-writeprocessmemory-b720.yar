rule TTP_XOR_WriteProcessMemory_b720 {
  strings:
    $key_b720 = { e0 52 [2] d2 70 [2] d4 45 [2] fa 45 [2] c5 59 }

  condition:
    any of them
}