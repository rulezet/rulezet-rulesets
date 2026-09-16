rule TTP_XOR_WriteProcessMemory_aa1f {
  strings:
    $key_aa1f = { fd 6d [2] cf 4f [2] c9 7a [2] e7 7a [2] d8 66 }

  condition:
    any of them
}