rule TTP_XOR_WriteProcessMemory_85fd {
  strings:
    $key_85fd = { d2 8f [2] e0 ad [2] e6 98 [2] c8 98 [2] f7 84 }

  condition:
    any of them
}