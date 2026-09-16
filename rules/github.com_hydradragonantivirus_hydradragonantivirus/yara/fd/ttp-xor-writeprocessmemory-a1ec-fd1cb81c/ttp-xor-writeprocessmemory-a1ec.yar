rule TTP_XOR_WriteProcessMemory_a1ec {
  strings:
    $key_a1ec = { f6 9e [2] c4 bc [2] c2 89 [2] ec 89 [2] d3 95 }

  condition:
    any of them
}