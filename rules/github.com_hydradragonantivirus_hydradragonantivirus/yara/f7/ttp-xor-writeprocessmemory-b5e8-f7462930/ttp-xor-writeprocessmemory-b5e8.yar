rule TTP_XOR_WriteProcessMemory_b5e8 {
  strings:
    $key_b5e8 = { e2 9a [2] d0 b8 [2] d6 8d [2] f8 8d [2] c7 91 }

  condition:
    any of them
}