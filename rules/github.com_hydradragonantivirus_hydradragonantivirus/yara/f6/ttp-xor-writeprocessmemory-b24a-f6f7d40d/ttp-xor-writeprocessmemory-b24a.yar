rule TTP_XOR_WriteProcessMemory_b24a {
  strings:
    $key_b24a = { e5 38 [2] d7 1a [2] d1 2f [2] ff 2f [2] c0 33 }

  condition:
    any of them
}