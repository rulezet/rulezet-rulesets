rule TTP_XOR_WriteProcessMemory_bde9 {
  strings:
    $key_bde9 = { ea 9b [2] d8 b9 [2] de 8c [2] f0 8c [2] cf 90 }

  condition:
    any of them
}