rule TTP_XOR_WriteProcessMemory_a73a {
  strings:
    $key_a73a = { f0 48 [2] c2 6a [2] c4 5f [2] ea 5f [2] d5 43 }

  condition:
    any of them
}