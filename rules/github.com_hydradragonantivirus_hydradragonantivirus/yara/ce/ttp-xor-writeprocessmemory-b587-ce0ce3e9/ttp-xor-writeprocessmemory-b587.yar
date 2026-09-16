rule TTP_XOR_WriteProcessMemory_b587 {
  strings:
    $key_b587 = { e2 f5 [2] d0 d7 [2] d6 e2 [2] f8 e2 [2] c7 fe }

  condition:
    any of them
}