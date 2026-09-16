rule TTP_XOR_WriteProcessMemory_947a {
  strings:
    $key_947a = { c3 08 [2] f1 2a [2] f7 1f [2] d9 1f [2] e6 03 }

  condition:
    any of them
}