rule TTP_XOR_WriteProcessMemory_937a {
  strings:
    $key_937a = { c4 08 [2] f6 2a [2] f0 1f [2] de 1f [2] e1 03 }

  condition:
    any of them
}