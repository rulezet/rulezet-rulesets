rule TTP_XOR_WriteProcessMemory_922a {
  strings:
    $key_922a = { c5 58 [2] f7 7a [2] f1 4f [2] df 4f [2] e0 53 }

  condition:
    any of them
}