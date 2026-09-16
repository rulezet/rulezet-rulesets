rule TTP_XOR_WriteProcessMemory_aa08 {
  strings:
    $key_aa08 = { fd 7a [2] cf 58 [2] c9 6d [2] e7 6d [2] d8 71 }

  condition:
    any of them
}