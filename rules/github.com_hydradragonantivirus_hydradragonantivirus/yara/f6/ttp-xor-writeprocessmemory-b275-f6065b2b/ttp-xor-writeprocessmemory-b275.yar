rule TTP_XOR_WriteProcessMemory_b275 {
  strings:
    $key_b275 = { e5 07 [2] d7 25 [2] d1 10 [2] ff 10 [2] c0 0c }

  condition:
    any of them
}