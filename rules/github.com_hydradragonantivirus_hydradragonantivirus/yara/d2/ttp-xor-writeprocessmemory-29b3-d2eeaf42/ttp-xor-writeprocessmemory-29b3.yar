rule TTP_XOR_WriteProcessMemory_29b3 {
  strings:
    $key_29b3 = { 7e c1 [2] 4c e3 [2] 4a d6 [2] 64 d6 [2] 5b ca }

  condition:
    any of them
}