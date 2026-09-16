rule TTP_XOR_WriteProcessMemory_b4a8 {
  strings:
    $key_b4a8 = { e3 da [2] d1 f8 [2] d7 cd [2] f9 cd [2] c6 d1 }

  condition:
    any of them
}