rule TTP_XOR_WriteProcessMemory_fc2a {
  strings:
    $key_fc2a = { ab 58 [2] 99 7a [2] 9f 4f [2] b1 4f [2] 8e 53 }

  condition:
    any of them
}