rule TTP_XOR_WriteProcessMemory_821a {
  strings:
    $key_821a = { d5 68 [2] e7 4a [2] e1 7f [2] cf 7f [2] f0 63 }

  condition:
    any of them
}