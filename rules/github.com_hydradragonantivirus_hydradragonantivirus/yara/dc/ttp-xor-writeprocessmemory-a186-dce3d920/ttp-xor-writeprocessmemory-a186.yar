rule TTP_XOR_WriteProcessMemory_a186 {
  strings:
    $key_a186 = { f6 f4 [2] c4 d6 [2] c2 e3 [2] ec e3 [2] d3 ff }

  condition:
    any of them
}