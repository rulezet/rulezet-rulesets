rule TTP_XOR_WriteProcessMemory_e40e {
  strings:
    $key_e40e = { b3 7c [2] 81 5e [2] 87 6b [2] a9 6b [2] 96 77 }

  condition:
    any of them
}