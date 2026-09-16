rule TTP_XOR_WriteProcessMemory_eb4c {
  strings:
    $key_eb4c = { bc 3e [2] 8e 1c [2] 88 29 [2] a6 29 [2] 99 35 }

  condition:
    any of them
}