rule TTP_XOR_WriteProcessMemory_3aac {
  strings:
    $key_3aac = { 6d de [2] 5f fc [2] 59 c9 [2] 77 c9 [2] 48 d5 }

  condition:
    any of them
}