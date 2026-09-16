rule TTP_XOR_WriteProcessMemory_e15a {
  strings:
    $key_e15a = { b6 28 [2] 84 0a [2] 82 3f [2] ac 3f [2] 93 23 }

  condition:
    any of them
}