rule TTP_XOR_WriteProcessMemory_8324 {
  strings:
    $key_8324 = { d4 56 [2] e6 74 [2] e0 41 [2] ce 41 [2] f1 5d }

  condition:
    any of them
}