rule TTP_XOR_WriteProcessMemory_b59c {
  strings:
    $key_b59c = { e2 ee [2] d0 cc [2] d6 f9 [2] f8 f9 [2] c7 e5 }

  condition:
    any of them
}