rule TTP_XOR_WriteProcessMemory_b5a8 {
  strings:
    $key_b5a8 = { e2 da [2] d0 f8 [2] d6 cd [2] f8 cd [2] c7 d1 }

  condition:
    any of them
}