rule TTP_XOR_WriteProcessMemory_aa1a {
  strings:
    $key_aa1a = { fd 68 [2] cf 4a [2] c9 7f [2] e7 7f [2] d8 63 }

  condition:
    any of them
}