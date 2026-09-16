rule TTP_XOR_WriteProcessMemory_fc1d {
  strings:
    $key_fc1d = { ab 6f [2] 99 4d [2] 9f 78 [2] b1 78 [2] 8e 64 }

  condition:
    any of them
}