rule TTP_XOR_WriteProcessMemory_b55a {
  strings:
    $key_b55a = { e2 28 [2] d0 0a [2] d6 3f [2] f8 3f [2] c7 23 }

  condition:
    any of them
}