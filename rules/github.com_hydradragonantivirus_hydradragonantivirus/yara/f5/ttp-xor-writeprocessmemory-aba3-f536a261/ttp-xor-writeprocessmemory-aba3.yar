rule TTP_XOR_WriteProcessMemory_aba3 {
  strings:
    $key_aba3 = { fc d1 [2] ce f3 [2] c8 c6 [2] e6 c6 [2] d9 da }

  condition:
    any of them
}