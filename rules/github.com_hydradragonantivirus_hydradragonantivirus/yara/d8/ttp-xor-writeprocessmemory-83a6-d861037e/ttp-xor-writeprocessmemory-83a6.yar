rule TTP_XOR_WriteProcessMemory_83a6 {
  strings:
    $key_83a6 = { d4 d4 [2] e6 f6 [2] e0 c3 [2] ce c3 [2] f1 df }

  condition:
    any of them
}