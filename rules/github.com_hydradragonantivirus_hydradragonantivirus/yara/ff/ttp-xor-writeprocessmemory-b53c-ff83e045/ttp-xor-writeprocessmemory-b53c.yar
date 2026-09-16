rule TTP_XOR_WriteProcessMemory_b53c {
  strings:
    $key_b53c = { e2 4e [2] d0 6c [2] d6 59 [2] f8 59 [2] c7 45 }

  condition:
    any of them
}