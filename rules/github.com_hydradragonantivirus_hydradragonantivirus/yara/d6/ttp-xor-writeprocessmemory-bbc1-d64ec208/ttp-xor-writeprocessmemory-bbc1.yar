rule TTP_XOR_WriteProcessMemory_bbc1 {
  strings:
    $key_bbc1 = { ec b3 [2] de 91 [2] d8 a4 [2] f6 a4 [2] c9 b8 }

  condition:
    any of them
}