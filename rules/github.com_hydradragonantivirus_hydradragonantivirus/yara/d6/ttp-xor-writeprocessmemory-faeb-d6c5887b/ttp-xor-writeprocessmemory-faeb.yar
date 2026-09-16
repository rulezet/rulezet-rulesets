rule TTP_XOR_WriteProcessMemory_faeb {
  strings:
    $key_faeb = { ad 99 [2] 9f bb [2] 99 8e [2] b7 8e [2] 88 92 }

  condition:
    any of them
}