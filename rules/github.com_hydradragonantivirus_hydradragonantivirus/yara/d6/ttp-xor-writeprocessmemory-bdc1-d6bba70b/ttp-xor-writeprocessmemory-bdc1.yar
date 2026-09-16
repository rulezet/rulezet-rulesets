rule TTP_XOR_WriteProcessMemory_bdc1 {
  strings:
    $key_bdc1 = { ea b3 [2] d8 91 [2] de a4 [2] f0 a4 [2] cf b8 }

  condition:
    any of them
}