rule TTP_XOR_WriteProcessMemory_bb05 {
  strings:
    $key_bb05 = { ec 77 [2] de 55 [2] d8 60 [2] f6 60 [2] c9 7c }

  condition:
    any of them
}