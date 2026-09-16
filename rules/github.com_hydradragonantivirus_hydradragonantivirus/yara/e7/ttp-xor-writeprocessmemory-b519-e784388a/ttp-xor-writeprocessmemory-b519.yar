rule TTP_XOR_WriteProcessMemory_b519 {
  strings:
    $key_b519 = { e2 6b [2] d0 49 [2] d6 7c [2] f8 7c [2] c7 60 }

  condition:
    any of them
}