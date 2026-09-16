rule TTP_XOR_WriteProcessMemory_a105 {
  strings:
    $key_a105 = { f6 77 [2] c4 55 [2] c2 60 [2] ec 60 [2] d3 7c }

  condition:
    any of them
}