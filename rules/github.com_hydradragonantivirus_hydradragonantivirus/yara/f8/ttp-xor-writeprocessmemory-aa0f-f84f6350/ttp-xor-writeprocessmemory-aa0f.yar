rule TTP_XOR_WriteProcessMemory_aa0f {
  strings:
    $key_aa0f = { fd 7d [2] cf 5f [2] c9 6a [2] e7 6a [2] d8 76 }

  condition:
    any of them
}