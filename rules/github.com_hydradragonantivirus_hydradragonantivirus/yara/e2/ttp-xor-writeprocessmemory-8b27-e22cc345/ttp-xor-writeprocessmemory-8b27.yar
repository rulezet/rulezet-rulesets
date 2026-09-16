rule TTP_XOR_WriteProcessMemory_8b27 {
  strings:
    $key_8b27 = { dc 55 [2] ee 77 [2] e8 42 [2] c6 42 [2] f9 5e }

  condition:
    any of them
}