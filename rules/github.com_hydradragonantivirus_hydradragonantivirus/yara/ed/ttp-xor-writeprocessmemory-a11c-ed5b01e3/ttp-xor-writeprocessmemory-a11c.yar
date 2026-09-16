rule TTP_XOR_WriteProcessMemory_a11c {
  strings:
    $key_a11c = { f6 6e [2] c4 4c [2] c2 79 [2] ec 79 [2] d3 65 }

  condition:
    any of them
}