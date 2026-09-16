rule TTP_XOR_WriteProcessMemory_942a {
  strings:
    $key_942a = { c3 58 [2] f1 7a [2] f7 4f [2] d9 4f [2] e6 53 }

  condition:
    any of them
}