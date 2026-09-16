rule TTP_XOR_WriteProcessMemory_b50a {
  strings:
    $key_b50a = { e2 78 [2] d0 5a [2] d6 6f [2] f8 6f [2] c7 73 }

  condition:
    any of them
}