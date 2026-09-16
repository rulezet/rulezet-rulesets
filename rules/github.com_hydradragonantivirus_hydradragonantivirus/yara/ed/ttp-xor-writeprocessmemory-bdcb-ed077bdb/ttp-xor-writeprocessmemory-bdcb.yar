rule TTP_XOR_WriteProcessMemory_bdcb {
  strings:
    $key_bdcb = { ea b9 [2] d8 9b [2] de ae [2] f0 ae [2] cf b2 }

  condition:
    any of them
}