rule TTP_XOR_WriteProcessMemory_8314 {
  strings:
    $key_8314 = { d4 66 [2] e6 44 [2] e0 71 [2] ce 71 [2] f1 6d }

  condition:
    any of them
}