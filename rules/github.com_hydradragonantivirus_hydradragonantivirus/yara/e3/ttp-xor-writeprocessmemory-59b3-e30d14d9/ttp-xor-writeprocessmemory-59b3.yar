rule TTP_XOR_WriteProcessMemory_59b3 {
  strings:
    $key_59b3 = { 0e c1 [2] 3c e3 [2] 3a d6 [2] 14 d6 [2] 2b ca }

  condition:
    any of them
}