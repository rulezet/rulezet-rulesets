rule TTP_XOR_WriteProcessMemory_bab3 {
  strings:
    $key_bab3 = { ed c1 [2] df e3 [2] d9 d6 [2] f7 d6 [2] c8 ca }

  condition:
    any of them
}