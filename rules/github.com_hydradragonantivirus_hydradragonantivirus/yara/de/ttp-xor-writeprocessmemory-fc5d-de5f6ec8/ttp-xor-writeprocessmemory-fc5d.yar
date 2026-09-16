rule TTP_XOR_WriteProcessMemory_fc5d {
  strings:
    $key_fc5d = { ab 2f [2] 99 0d [2] 9f 38 [2] b1 38 [2] 8e 24 }

  condition:
    any of them
}