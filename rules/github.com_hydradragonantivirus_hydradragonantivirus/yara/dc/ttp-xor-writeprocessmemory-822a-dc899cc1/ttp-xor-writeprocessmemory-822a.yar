rule TTP_XOR_WriteProcessMemory_822a {
  strings:
    $key_822a = { d5 58 [2] e7 7a [2] e1 4f [2] cf 4f [2] f0 53 }

  condition:
    any of them
}