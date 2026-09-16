rule TTP_XOR_WriteProcessMemory_b22f {
  strings:
    $key_b22f = { e5 5d [2] d7 7f [2] d1 4a [2] ff 4a [2] c0 56 }

  condition:
    any of them
}