rule TTP_XOR_WriteProcessMemory_aba7 {
  strings:
    $key_aba7 = { fc d5 [2] ce f7 [2] c8 c2 [2] e6 c2 [2] d9 de }

  condition:
    any of them
}