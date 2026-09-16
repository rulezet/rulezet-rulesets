rule TTP_XOR_WriteProcessMemory_f97a {
  strings:
    $key_f97a = { ae 08 [2] 9c 2a [2] 9a 1f [2] b4 1f [2] 8b 03 }

  condition:
    any of them
}