rule TTP_XOR_WriteProcessMemory_bd91 {
  strings:
    $key_bd91 = { ea e3 [2] d8 c1 [2] de f4 [2] f0 f4 [2] cf e8 }

  condition:
    any of them
}