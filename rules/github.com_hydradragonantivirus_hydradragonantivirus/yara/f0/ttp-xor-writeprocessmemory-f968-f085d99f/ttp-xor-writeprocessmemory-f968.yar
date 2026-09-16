rule TTP_XOR_WriteProcessMemory_f968 {
  strings:
    $key_f968 = { ae 1a [2] 9c 38 [2] 9a 0d [2] b4 0d [2] 8b 11 }

  condition:
    any of them
}