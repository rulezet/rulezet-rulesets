rule TTP_XOR_WriteProcessMemory_ebdf {
  strings:
    $key_ebdf = { bc ad [2] 8e 8f [2] 88 ba [2] a6 ba [2] 99 a6 }

  condition:
    any of them
}