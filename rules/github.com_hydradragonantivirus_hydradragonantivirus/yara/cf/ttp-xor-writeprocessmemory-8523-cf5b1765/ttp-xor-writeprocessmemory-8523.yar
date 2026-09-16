rule TTP_XOR_WriteProcessMemory_8523 {
  strings:
    $key_8523 = { d2 51 [2] e0 73 [2] e6 46 [2] c8 46 [2] f7 5a }

  condition:
    any of them
}