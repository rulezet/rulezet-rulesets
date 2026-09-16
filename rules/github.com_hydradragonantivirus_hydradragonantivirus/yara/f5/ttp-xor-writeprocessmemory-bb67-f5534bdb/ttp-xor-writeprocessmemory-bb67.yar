rule TTP_XOR_WriteProcessMemory_bb67 {
  strings:
    $key_bb67 = { ec 15 [2] de 37 [2] d8 02 [2] f6 02 [2] c9 1e }

  condition:
    any of them
}