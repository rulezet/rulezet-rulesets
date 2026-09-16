rule TTP_XOR_WriteProcessMemory_fc2f {
  strings:
    $key_fc2f = { ab 5d [2] 99 7f [2] 9f 4a [2] b1 4a [2] 8e 56 }

  condition:
    any of them
}