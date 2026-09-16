rule TTP_XOR_WriteProcessMemory_b40e {
  strings:
    $key_b40e = { e3 7c [2] d1 5e [2] d7 6b [2] f9 6b [2] c6 77 }

  condition:
    any of them
}