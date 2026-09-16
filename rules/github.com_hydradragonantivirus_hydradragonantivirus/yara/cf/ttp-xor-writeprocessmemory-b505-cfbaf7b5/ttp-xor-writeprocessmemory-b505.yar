rule TTP_XOR_WriteProcessMemory_b505 {
  strings:
    $key_b505 = { e2 77 [2] d0 55 [2] d6 60 [2] f8 60 [2] c7 7c }

  condition:
    any of them
}