rule TTP_XOR_WriteProcessMemory_8a95 {
  strings:
    $key_8a95 = { dd e7 [2] ef c5 [2] e9 f0 [2] c7 f0 [2] f8 ec }

  condition:
    any of them
}