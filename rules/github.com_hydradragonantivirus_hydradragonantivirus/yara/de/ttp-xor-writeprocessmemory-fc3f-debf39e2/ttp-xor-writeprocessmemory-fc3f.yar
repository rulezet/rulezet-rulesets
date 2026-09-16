rule TTP_XOR_WriteProcessMemory_fc3f {
  strings:
    $key_fc3f = { ab 4d [2] 99 6f [2] 9f 5a [2] b1 5a [2] 8e 46 }

  condition:
    any of them
}