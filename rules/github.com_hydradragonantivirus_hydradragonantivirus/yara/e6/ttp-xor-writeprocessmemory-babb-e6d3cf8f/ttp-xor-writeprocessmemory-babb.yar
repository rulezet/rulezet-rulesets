rule TTP_XOR_WriteProcessMemory_babb {
  strings:
    $key_babb = { ed c9 [2] df eb [2] d9 de [2] f7 de [2] c8 c2 }

  condition:
    any of them
}