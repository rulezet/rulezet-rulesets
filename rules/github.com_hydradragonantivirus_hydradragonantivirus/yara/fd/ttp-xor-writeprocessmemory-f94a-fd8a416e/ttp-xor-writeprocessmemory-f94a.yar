rule TTP_XOR_WriteProcessMemory_f94a {
  strings:
    $key_f94a = { ae 38 [2] 9c 1a [2] 9a 2f [2] b4 2f [2] 8b 33 }

  condition:
    any of them
}