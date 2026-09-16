rule TTP_XOR_WriteProcessMemory_a19b {
  strings:
    $key_a19b = { f6 e9 [2] c4 cb [2] c2 fe [2] ec fe [2] d3 e2 }

  condition:
    any of them
}