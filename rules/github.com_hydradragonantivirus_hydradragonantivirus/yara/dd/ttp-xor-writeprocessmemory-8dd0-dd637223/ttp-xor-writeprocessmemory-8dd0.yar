rule TTP_XOR_WriteProcessMemory_8dd0 {
  strings:
    $key_8dd0 = { da a2 [2] e8 80 [2] ee b5 [2] c0 b5 [2] ff a9 }

  condition:
    any of them
}