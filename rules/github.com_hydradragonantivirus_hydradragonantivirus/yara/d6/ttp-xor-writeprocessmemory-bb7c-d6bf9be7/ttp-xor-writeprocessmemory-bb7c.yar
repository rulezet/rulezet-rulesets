rule TTP_XOR_WriteProcessMemory_bb7c {
  strings:
    $key_bb7c = { ec 0e [2] de 2c [2] d8 19 [2] f6 19 [2] c9 05 }

  condition:
    any of them
}