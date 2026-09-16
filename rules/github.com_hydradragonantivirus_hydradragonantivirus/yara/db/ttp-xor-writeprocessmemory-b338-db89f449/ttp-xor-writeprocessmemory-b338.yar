rule TTP_XOR_WriteProcessMemory_b338 {
  strings:
    $key_b338 = { e4 4a [2] d6 68 [2] d0 5d [2] fe 5d [2] c1 41 }

  condition:
    any of them
}