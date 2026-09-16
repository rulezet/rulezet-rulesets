rule TTP_XOR_WriteProcessMemory_fc1c {
  strings:
    $key_fc1c = { ab 6e [2] 99 4c [2] 9f 79 [2] b1 79 [2] 8e 65 }

  condition:
    any of them
}