rule TTP_XOR_WriteProcessMemory_946a {
  strings:
    $key_946a = { c3 18 [2] f1 3a [2] f7 0f [2] d9 0f [2] e6 13 }

  condition:
    any of them
}