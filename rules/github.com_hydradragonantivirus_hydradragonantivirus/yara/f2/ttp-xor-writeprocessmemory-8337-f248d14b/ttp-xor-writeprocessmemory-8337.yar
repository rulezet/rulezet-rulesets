rule TTP_XOR_WriteProcessMemory_8337 {
  strings:
    $key_8337 = { d4 45 [2] e6 67 [2] e0 52 [2] ce 52 [2] f1 4e }

  condition:
    any of them
}