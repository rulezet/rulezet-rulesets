rule TTP_XOR_WriteProcessMemory_b202 {
  strings:
    $key_b202 = { e5 70 [2] d7 52 [2] d1 67 [2] ff 67 [2] c0 7b }

  condition:
    any of them
}