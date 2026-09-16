rule TTP_XOR_WriteProcessMemory_bb36 {
  strings:
    $key_bb36 = { ec 44 [2] de 66 [2] d8 53 [2] f6 53 [2] c9 4f }

  condition:
    any of them
}