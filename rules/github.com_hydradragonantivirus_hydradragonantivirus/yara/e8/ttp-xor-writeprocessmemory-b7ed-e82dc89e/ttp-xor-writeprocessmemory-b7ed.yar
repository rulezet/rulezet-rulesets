rule TTP_XOR_WriteProcessMemory_b7ed {
  strings:
    $key_b7ed = { e0 9f [2] d2 bd [2] d4 88 [2] fa 88 [2] c5 94 }

  condition:
    any of them
}