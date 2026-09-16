rule TTP_XOR_WriteProcessMemory_ebdd {
  strings:
    $key_ebdd = { bc af [2] 8e 8d [2] 88 b8 [2] a6 b8 [2] 99 a4 }

  condition:
    any of them
}