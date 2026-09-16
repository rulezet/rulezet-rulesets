rule TTP_XOR_WriteProcessMemory_eb8f {
  strings:
    $key_eb8f = { bc fd [2] 8e df [2] 88 ea [2] a6 ea [2] 99 f6 }

  condition:
    any of them
}