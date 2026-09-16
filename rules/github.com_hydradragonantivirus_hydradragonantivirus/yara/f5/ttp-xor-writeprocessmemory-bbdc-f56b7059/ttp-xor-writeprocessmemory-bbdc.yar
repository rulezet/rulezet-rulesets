rule TTP_XOR_WriteProcessMemory_bbdc {
  strings:
    $key_bbdc = { ec ae [2] de 8c [2] d8 b9 [2] f6 b9 [2] c9 a5 }

  condition:
    any of them
}