rule TTP_XOR_WriteProcessMemory_b31a {
  strings:
    $key_b31a = { e4 68 [2] d6 4a [2] d0 7f [2] fe 7f [2] c1 63 }

  condition:
    any of them
}