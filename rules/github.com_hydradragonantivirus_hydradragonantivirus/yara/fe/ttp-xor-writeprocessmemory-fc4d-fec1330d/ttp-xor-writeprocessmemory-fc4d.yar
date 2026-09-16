rule TTP_XOR_WriteProcessMemory_fc4d {
  strings:
    $key_fc4d = { ab 3f [2] 99 1d [2] 9f 28 [2] b1 28 [2] 8e 34 }

  condition:
    any of them
}