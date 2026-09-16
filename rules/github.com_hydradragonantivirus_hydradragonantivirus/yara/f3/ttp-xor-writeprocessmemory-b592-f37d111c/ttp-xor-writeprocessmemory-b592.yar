rule TTP_XOR_WriteProcessMemory_b592 {
  strings:
    $key_b592 = { e2 e0 [2] d0 c2 [2] d6 f7 [2] f8 f7 [2] c7 eb }

  condition:
    any of them
}