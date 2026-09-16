rule TTP_XOR_WriteProcessMemory_aa38 {
  strings:
    $key_aa38 = { fd 4a [2] cf 68 [2] c9 5d [2] e7 5d [2] d8 41 }

  condition:
    any of them
}