rule TTP_XOR_WriteProcessMemory_8a57 {
  strings:
    $key_8a57 = { dd 25 [2] ef 07 [2] e9 32 [2] c7 32 [2] f8 2e }

  condition:
    any of them
}