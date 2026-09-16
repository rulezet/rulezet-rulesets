rule TTP_XOR_WriteProcessMemory_aaed {
  strings:
    $key_aaed = { fd 9f [2] cf bd [2] c9 88 [2] e7 88 [2] d8 94 }

  condition:
    any of them
}