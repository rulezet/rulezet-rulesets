rule TTP_XOR_WriteProcessMemory_b5a2 {
  strings:
    $key_b5a2 = { e2 d0 [2] d0 f2 [2] d6 c7 [2] f8 c7 [2] c7 db }

  condition:
    any of them
}