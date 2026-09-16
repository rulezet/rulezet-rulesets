rule TTP_XOR_WriteProcessMemory_bbc0 {
  strings:
    $key_bbc0 = { ec b2 [2] de 90 [2] d8 a5 [2] f6 a5 [2] c9 b9 }

  condition:
    any of them
}