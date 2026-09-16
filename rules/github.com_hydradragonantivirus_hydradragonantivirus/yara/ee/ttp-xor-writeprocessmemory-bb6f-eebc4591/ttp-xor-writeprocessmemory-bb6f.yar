rule TTP_XOR_WriteProcessMemory_bb6f {
  strings:
    $key_bb6f = { ec 1d [2] de 3f [2] d8 0a [2] f6 0a [2] c9 16 }

  condition:
    any of them
}