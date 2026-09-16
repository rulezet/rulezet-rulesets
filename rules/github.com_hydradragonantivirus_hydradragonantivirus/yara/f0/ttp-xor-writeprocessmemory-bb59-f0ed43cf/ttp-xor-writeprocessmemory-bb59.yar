rule TTP_XOR_WriteProcessMemory_bb59 {
  strings:
    $key_bb59 = { ec 2b [2] de 09 [2] d8 3c [2] f6 3c [2] c9 20 }

  condition:
    any of them
}