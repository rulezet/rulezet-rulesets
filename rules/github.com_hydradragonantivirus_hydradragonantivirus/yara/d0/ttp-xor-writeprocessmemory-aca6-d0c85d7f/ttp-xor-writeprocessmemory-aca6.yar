rule TTP_XOR_WriteProcessMemory_aca6 {
  strings:
    $key_aca6 = { fb d4 [2] c9 f6 [2] cf c3 [2] e1 c3 [2] de df }

  condition:
    any of them
}