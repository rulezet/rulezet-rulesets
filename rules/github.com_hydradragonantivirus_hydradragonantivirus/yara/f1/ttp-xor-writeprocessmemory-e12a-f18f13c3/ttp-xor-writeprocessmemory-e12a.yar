rule TTP_XOR_WriteProcessMemory_e12a {
  strings:
    $key_e12a = { b6 58 [2] 84 7a [2] 82 4f [2] ac 4f [2] 93 53 }

  condition:
    any of them
}