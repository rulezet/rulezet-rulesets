rule TTP_XOR_WriteProcessMemory_b4f4 {
  strings:
    $key_b4f4 = { e3 86 [2] d1 a4 [2] d7 91 [2] f9 91 [2] c6 8d }

  condition:
    any of them
}