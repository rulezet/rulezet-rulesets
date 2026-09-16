rule TTP_XOR_WriteProcessMemory_3aff {
  strings:
    $key_3aff = { 6d 8d [2] 5f af [2] 59 9a [2] 77 9a [2] 48 86 }

  condition:
    any of them
}