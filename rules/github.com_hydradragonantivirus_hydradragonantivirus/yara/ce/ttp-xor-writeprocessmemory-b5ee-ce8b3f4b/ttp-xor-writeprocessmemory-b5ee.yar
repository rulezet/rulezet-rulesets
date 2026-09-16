rule TTP_XOR_WriteProcessMemory_b5ee {
  strings:
    $key_b5ee = { e2 9c [2] d0 be [2] d6 8b [2] f8 8b [2] c7 97 }

  condition:
    any of them
}