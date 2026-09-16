rule TTP_XOR_WriteProcessMemory_a40c {
  strings:
    $key_a40c = { f3 7e [2] c1 5c [2] c7 69 [2] e9 69 [2] d6 75 }

  condition:
    any of them
}