rule TTP_XOR_WriteProcessMemory_bbd7 {
  strings:
    $key_bbd7 = { ec a5 [2] de 87 [2] d8 b2 [2] f6 b2 [2] c9 ae }

  condition:
    any of them
}