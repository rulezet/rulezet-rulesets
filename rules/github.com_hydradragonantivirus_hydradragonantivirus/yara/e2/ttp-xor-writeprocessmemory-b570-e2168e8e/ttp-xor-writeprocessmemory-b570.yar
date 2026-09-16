rule TTP_XOR_WriteProcessMemory_b570 {
  strings:
    $key_b570 = { e2 02 [2] d0 20 [2] d6 15 [2] f8 15 [2] c7 09 }

  condition:
    any of them
}