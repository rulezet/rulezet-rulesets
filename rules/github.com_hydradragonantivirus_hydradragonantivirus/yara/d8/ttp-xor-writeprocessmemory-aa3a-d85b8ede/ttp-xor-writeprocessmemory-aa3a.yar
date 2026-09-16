rule TTP_XOR_WriteProcessMemory_aa3a {
  strings:
    $key_aa3a = { fd 48 [2] cf 6a [2] c9 5f [2] e7 5f [2] d8 43 }

  condition:
    any of them
}