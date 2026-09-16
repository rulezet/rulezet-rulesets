rule TTP_XOR_WriteProcessMemory_a20e {
  strings:
    $key_a20e = { f5 7c [2] c7 5e [2] c1 6b [2] ef 6b [2] d0 77 }

  condition:
    any of them
}