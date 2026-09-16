rule TTP_XOR_WriteProcessMemory_f387 {
  strings:
    $key_f387 = { a4 f5 [2] 96 d7 [2] 90 e2 [2] be e2 [2] 81 fe }

  condition:
    any of them
}