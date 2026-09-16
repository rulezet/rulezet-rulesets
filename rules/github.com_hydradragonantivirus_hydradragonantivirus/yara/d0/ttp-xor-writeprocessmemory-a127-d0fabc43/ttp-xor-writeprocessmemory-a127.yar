rule TTP_XOR_WriteProcessMemory_a127 {
  strings:
    $key_a127 = { f6 55 [2] c4 77 [2] c2 42 [2] ec 42 [2] d3 5e }

  condition:
    any of them
}