rule TTP_XOR_WriteProcessMemory_b51f {
  strings:
    $key_b51f = { e2 6d [2] d0 4f [2] d6 7a [2] f8 7a [2] c7 66 }

  condition:
    any of them
}