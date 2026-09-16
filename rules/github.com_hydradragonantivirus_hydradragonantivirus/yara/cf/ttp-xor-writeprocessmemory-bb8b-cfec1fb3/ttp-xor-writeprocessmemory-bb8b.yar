rule TTP_XOR_WriteProcessMemory_bb8b {
  strings:
    $key_bb8b = { ec f9 [2] de db [2] d8 ee [2] f6 ee [2] c9 f2 }

  condition:
    any of them
}