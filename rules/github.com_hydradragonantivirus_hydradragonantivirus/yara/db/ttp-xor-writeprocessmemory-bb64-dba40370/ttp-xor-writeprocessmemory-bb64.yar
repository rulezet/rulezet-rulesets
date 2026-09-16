rule TTP_XOR_WriteProcessMemory_bb64 {
  strings:
    $key_bb64 = { ec 16 [2] de 34 [2] d8 01 [2] f6 01 [2] c9 1d }

  condition:
    any of them
}