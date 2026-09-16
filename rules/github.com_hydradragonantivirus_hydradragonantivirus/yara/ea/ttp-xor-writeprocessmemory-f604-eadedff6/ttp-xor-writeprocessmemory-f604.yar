rule TTP_XOR_WriteProcessMemory_f604 {
  strings:
    $key_f604 = { a1 76 [2] 93 54 [2] 95 61 [2] bb 61 [2] 84 7d }

  condition:
    any of them
}