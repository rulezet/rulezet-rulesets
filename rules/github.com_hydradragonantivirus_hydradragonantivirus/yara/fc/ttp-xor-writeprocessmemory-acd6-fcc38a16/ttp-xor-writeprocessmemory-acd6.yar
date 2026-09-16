rule TTP_XOR_WriteProcessMemory_acd6 {
  strings:
    $key_acd6 = { fb a4 [2] c9 86 [2] cf b3 [2] e1 b3 [2] de af }

  condition:
    any of them
}