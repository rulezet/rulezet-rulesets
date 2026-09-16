rule TTP_XOR_WriteProcessMemory_c95a {
  strings:
    $key_c95a = { 9e 28 [2] ac 0a [2] aa 3f [2] 84 3f [2] bb 23 }

  condition:
    any of them
}