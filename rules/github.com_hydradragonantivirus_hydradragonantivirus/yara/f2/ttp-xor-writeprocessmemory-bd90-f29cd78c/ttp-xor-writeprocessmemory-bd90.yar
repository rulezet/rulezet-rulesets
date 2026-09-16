rule TTP_XOR_WriteProcessMemory_bd90 {
  strings:
    $key_bd90 = { ea e2 [2] d8 c0 [2] de f5 [2] f0 f5 [2] cf e9 }

  condition:
    any of them
}