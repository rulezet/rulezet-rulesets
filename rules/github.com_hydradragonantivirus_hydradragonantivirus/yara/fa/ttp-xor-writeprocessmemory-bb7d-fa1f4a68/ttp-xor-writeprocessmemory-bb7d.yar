rule TTP_XOR_WriteProcessMemory_bb7d {
  strings:
    $key_bb7d = { ec 0f [2] de 2d [2] d8 18 [2] f6 18 [2] c9 04 }

  condition:
    any of them
}