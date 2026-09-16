rule TTP_XOR_WriteProcessMemory_b593 {
  strings:
    $key_b593 = { e2 e1 [2] d0 c3 [2] d6 f6 [2] f8 f6 [2] c7 ea }

  condition:
    any of them
}