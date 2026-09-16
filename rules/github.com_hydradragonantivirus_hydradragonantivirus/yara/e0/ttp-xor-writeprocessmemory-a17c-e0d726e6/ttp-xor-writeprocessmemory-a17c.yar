rule TTP_XOR_WriteProcessMemory_a17c {
  strings:
    $key_a17c = { f6 0e [2] c4 2c [2] c2 19 [2] ec 19 [2] d3 05 }

  condition:
    any of them
}