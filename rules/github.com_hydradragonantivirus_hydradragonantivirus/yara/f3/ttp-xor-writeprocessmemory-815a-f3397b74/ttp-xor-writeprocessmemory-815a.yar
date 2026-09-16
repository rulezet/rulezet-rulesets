rule TTP_XOR_WriteProcessMemory_815a {
  strings:
    $key_815a = { d6 28 [2] e4 0a [2] e2 3f [2] cc 3f [2] f3 23 }

  condition:
    any of them
}