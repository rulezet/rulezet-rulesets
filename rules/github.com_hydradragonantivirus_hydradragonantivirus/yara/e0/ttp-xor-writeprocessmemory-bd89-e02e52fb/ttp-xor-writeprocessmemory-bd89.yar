rule TTP_XOR_WriteProcessMemory_bd89 {
  strings:
    $key_bd89 = { ea fb [2] d8 d9 [2] de ec [2] f0 ec [2] cf f0 }

  condition:
    any of them
}