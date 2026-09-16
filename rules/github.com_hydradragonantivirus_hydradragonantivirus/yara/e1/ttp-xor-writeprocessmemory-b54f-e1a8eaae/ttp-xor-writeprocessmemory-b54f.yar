rule TTP_XOR_WriteProcessMemory_b54f {
  strings:
    $key_b54f = { e2 3d [2] d0 1f [2] d6 2a [2] f8 2a [2] c7 36 }

  condition:
    any of them
}