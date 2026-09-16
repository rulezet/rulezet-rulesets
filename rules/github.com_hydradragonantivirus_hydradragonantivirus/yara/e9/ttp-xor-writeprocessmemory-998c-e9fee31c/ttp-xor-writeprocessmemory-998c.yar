rule TTP_XOR_WriteProcessMemory_998c {
  strings:
    $key_998c = { ce fe [2] fc dc [2] fa e9 [2] d4 e9 [2] eb f5 }

  condition:
    any of them
}