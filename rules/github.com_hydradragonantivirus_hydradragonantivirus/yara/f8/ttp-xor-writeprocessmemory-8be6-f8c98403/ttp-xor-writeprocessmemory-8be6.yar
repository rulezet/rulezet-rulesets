rule TTP_XOR_WriteProcessMemory_8be6 {
  strings:
    $key_8be6 = { dc 94 [2] ee b6 [2] e8 83 [2] c6 83 [2] f9 9f }

  condition:
    any of them
}