rule TTP_XOR_WriteProcessMemory_8a97 {
  strings:
    $key_8a97 = { dd e5 [2] ef c7 [2] e9 f2 [2] c7 f2 [2] f8 ee }

  condition:
    any of them
}