rule TTP_XOR_WriteProcessMemory_bb18 {
  strings:
    $key_bb18 = { ec 6a [2] de 48 [2] d8 7d [2] f6 7d [2] c9 61 }

  condition:
    any of them
}