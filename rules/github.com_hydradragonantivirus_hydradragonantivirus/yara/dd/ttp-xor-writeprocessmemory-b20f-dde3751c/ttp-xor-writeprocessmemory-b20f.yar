rule TTP_XOR_WriteProcessMemory_b20f {
  strings:
    $key_b20f = { e5 7d [2] d7 5f [2] d1 6a [2] ff 6a [2] c0 76 }

  condition:
    any of them
}