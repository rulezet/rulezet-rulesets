rule TTP_XOR_WriteProcessMemory_b1ed {
  strings:
    $key_b1ed = { e6 9f [2] d4 bd [2] d2 88 [2] fc 88 [2] c3 94 }

  condition:
    any of them
}