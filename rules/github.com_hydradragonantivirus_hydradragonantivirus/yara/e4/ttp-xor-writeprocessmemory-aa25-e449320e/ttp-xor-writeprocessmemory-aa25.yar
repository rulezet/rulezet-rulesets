rule TTP_XOR_WriteProcessMemory_aa25 {
  strings:
    $key_aa25 = { fd 57 [2] cf 75 [2] c9 40 [2] e7 40 [2] d8 5c }

  condition:
    any of them
}