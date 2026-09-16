rule TTP_XOR_WriteProcessMemory_09b3 {
  strings:
    $key_09b3 = { 5e c1 [2] 6c e3 [2] 6a d6 [2] 44 d6 [2] 7b ca }

  condition:
    any of them
}