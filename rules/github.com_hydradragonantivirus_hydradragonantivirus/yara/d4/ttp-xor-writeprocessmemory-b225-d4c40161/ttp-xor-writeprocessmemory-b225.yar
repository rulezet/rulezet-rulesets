rule TTP_XOR_WriteProcessMemory_b225 {
  strings:
    $key_b225 = { e5 57 [2] d7 75 [2] d1 40 [2] ff 40 [2] c0 5c }

  condition:
    any of them
}