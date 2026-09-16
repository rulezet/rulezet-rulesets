rule TTP_XOR_WriteProcessMemory_bb3a {
  strings:
    $key_bb3a = { ec 48 [2] de 6a [2] d8 5f [2] f6 5f [2] c9 43 }

  condition:
    any of them
}