rule TTP_XOR_WriteProcessMemory_b5d7 {
  strings:
    $key_b5d7 = { e2 a5 [2] d0 87 [2] d6 b2 [2] f8 b2 [2] c7 ae }

  condition:
    any of them
}