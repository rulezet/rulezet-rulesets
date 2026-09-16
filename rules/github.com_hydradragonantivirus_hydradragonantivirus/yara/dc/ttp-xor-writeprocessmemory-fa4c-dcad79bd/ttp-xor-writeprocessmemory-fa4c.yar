rule TTP_XOR_WriteProcessMemory_fa4c {
  strings:
    $key_fa4c = { ad 3e [2] 9f 1c [2] 99 29 [2] b7 29 [2] 88 35 }

  condition:
    any of them
}