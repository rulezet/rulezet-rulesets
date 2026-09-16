rule TTP_XOR_WriteProcessMemory_aca3 {
  strings:
    $key_aca3 = { fb d1 [2] c9 f3 [2] cf c6 [2] e1 c6 [2] de da }

  condition:
    any of them
}